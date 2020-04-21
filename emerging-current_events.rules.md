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



#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Malvertising drive by kit encountered - Loading..."; flow:established,to_client; content:"HTTP/1"; depth:6; content:"<html><head></head><body>Loading...<div id=|22|page|22| style=|22|display|3a| none|22|>"; nocase; reference:url,doc.emergingthreats.net/2011223; classtype:bad-unknown; sid:2011223; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011223
`#alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Malvertising drive by kit encountered - Loading..."; flow:established,to_client; content:"HTTP/1"; depth:6; content:"<html><head></head><body>Loading...<div id=|22|page|22| style=|22|display|3a| none|22|>"; nocase; reference:url,doc.emergingthreats.net/2011223; classtype:bad-unknown; sid:2011223; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Malvertising drive by kit encountered - Loading...** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,doc.emergingthreats.net/2011223

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET CURRENT_EVENTS SWF served from /tmp/ "; flow:established,to_server; content:"/tmp/"; http_uri; fast_pattern; content:".swf"; http_uri; pcre:"/\/tmp\/[^\/]+\.swf$/U"; classtype:bad-unknown; sid:2011970; rev:1; metadata:created_at 2010_11_23, updated_at 2010_11_23;)

# 2011970
`#alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET CURRENT_EVENTS SWF served from /tmp/ "; flow:established,to_server; content:"/tmp/"; http_uri; fast_pattern; content:".swf"; http_uri; pcre:"/\/tmp\/[^\/]+\.swf$/U"; classtype:bad-unknown; sid:2011970; rev:1; metadata:created_at 2010_11_23, updated_at 2010_11_23;)
` 

Name : **SWF served from /tmp/ ** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-11-23

Last modified date : 2010-11-23

Rev version : 1

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET CURRENT_EVENTS Possible Neosploit Toolkit download"; flow:established,to_server; content:"GET"; nocase; http_method; content:"/GNH11.exe"; http_uri; nocase; reference:url,www.malwareurl.com/listing.php?domain=piadraspgdw.com; reference:url,labs.m86security.com/2011/01/shedding-light-on-the-neosploit-exploit-kit; classtype:trojan-activity; sid:2012333; rev:3; metadata:created_at 2011_02_22, updated_at 2011_02_22;)

# 2012333
`#alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET CURRENT_EVENTS Possible Neosploit Toolkit download"; flow:established,to_server; content:"GET"; nocase; http_method; content:"/GNH11.exe"; http_uri; nocase; reference:url,www.malwareurl.com/listing.php?domain=piadraspgdw.com; reference:url,labs.m86security.com/2011/01/shedding-light-on-the-neosploit-exploit-kit; classtype:trojan-activity; sid:2012333; rev:3; metadata:created_at 2011_02_22, updated_at 2011_02_22;)
` 

Name : **Possible Neosploit Toolkit download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.malwareurl.com/listing.php?domain=piadraspgdw.com|url,labs.m86security.com/2011/01/shedding-light-on-the-neosploit-exploit-kit

CVE reference : Not defined

Creation date : 2011-02-22

Last modified date : 2011-02-22

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS RetroGuard Obfuscated JAR likely part of hostile exploit kit"; flow:established,from_server; content:"classPK"; content:"|20|by|20|RetroGuard|20|Lite|20|"; metadata: former_category CURRENT_EVENTS; reference:url,www.retrologic.com; classtype:trojan-activity; sid:2012518; rev:2; metadata:created_at 2011_03_17, updated_at 2011_03_17;)

# 2012518
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS RetroGuard Obfuscated JAR likely part of hostile exploit kit"; flow:established,from_server; content:"classPK"; content:"|20|by|20|RetroGuard|20|Lite|20|"; metadata: former_category CURRENT_EVENTS; reference:url,www.retrologic.com; classtype:trojan-activity; sid:2012518; rev:2; metadata:created_at 2011_03_17, updated_at 2011_03_17;)
` 

Name : **RetroGuard Obfuscated JAR likely part of hostile exploit kit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.retrologic.com

CVE reference : Not defined

Creation date : 2011-03-17

Last modified date : 2011-03-17

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS WindowsLive Imposter Site WindowsLive.png"; flow:established,to_server; content:"/images/WindowsLive.png"; http_uri; depth:23; classtype:bad-unknown; sid:2012529; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)

# 2012529
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS WindowsLive Imposter Site WindowsLive.png"; flow:established,to_server; content:"/images/WindowsLive.png"; http_uri; depth:23; classtype:bad-unknown; sid:2012529; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)
` 

Name : **WindowsLive Imposter Site WindowsLive.png** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-21

Last modified date : 2011-03-21

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS WindowsLive Imposter Site Landing Page"; flow:established,from_server; content:"<title>MWL</title>"; classtype:bad-unknown; sid:2012530; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)

# 2012530
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS WindowsLive Imposter Site Landing Page"; flow:established,from_server; content:"<title>MWL</title>"; classtype:bad-unknown; sid:2012530; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)
` 

Name : **WindowsLive Imposter Site Landing Page** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-21

Last modified date : 2011-03-21

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS WindowsLive Imposter Site blt .png"; flow:established,to_server; content:"/images/blt"; http_uri; depth:11; content:".png"; http_uri; within:6; classtype:bad-unknown; sid:2012531; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)

# 2012531
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS WindowsLive Imposter Site blt .png"; flow:established,to_server; content:"/images/blt"; http_uri; depth:11; content:".png"; http_uri; within:6; classtype:bad-unknown; sid:2012531; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)
` 

Name : **WindowsLive Imposter Site blt .png** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-21

Last modified date : 2011-03-21

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS WindowsLive Imposter Site Payload Download"; flow:established,to_server; content:"/MRT/update/"; http_uri; depth:12; content:".exe"; http_uri; classtype:bad-unknown; sid:2012532; rev:2; metadata:created_at 2011_03_21, updated_at 2011_03_21;)

# 2012532
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS WindowsLive Imposter Site Payload Download"; flow:established,to_server; content:"/MRT/update/"; http_uri; depth:12; content:".exe"; http_uri; classtype:bad-unknown; sid:2012532; rev:2; metadata:created_at 2011_03_21, updated_at 2011_03_21;)
` 

Name : **WindowsLive Imposter Site Payload Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-21

Last modified date : 2011-03-21

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Java Exploit io.exe download served"; flow:established,from_server; content:"|3b 20|filename=io.exe|0d 0a|"; fast_pattern; classtype:trojan-activity; sid:2012610; rev:2; metadata:created_at 2011_03_30, updated_at 2011_03_30;)

# 2012610
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Java Exploit io.exe download served"; flow:established,from_server; content:"|3b 20|filename=io.exe|0d 0a|"; fast_pattern; classtype:trojan-activity; sid:2012610; rev:2; metadata:created_at 2011_03_30, updated_at 2011_03_30;)
` 

Name : **Java Exploit io.exe download served** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-30

Last modified date : 2011-03-30

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Internal WebServer Compromised By Lizamoon Mass SQL-Injection Attacks"; flow:established,from_server; content:"</title><script src=http|3a|//"; nocase; content:"/ur.php></script>"; within:100; reference:url,malwaresurvival.net/tag/lizamoon-com/; classtype:web-application-attack; sid:2012614; rev:5; metadata:created_at 2011_03_31, updated_at 2011_03_31;)

# 2012614
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Internal WebServer Compromised By Lizamoon Mass SQL-Injection Attacks"; flow:established,from_server; content:"</title><script src=http|3a|//"; nocase; content:"/ur.php></script>"; within:100; reference:url,malwaresurvival.net/tag/lizamoon-com/; classtype:web-application-attack; sid:2012614; rev:5; metadata:created_at 2011_03_31, updated_at 2011_03_31;)
` 

Name : **Internal WebServer Compromised By Lizamoon Mass SQL-Injection Attacks** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,malwaresurvival.net/tag/lizamoon-com/

CVE reference : Not defined

Creation date : 2011-03-31

Last modified date : 2011-03-31

Rev version : 5

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Potential Lizamoon Client Request /ur.php"; flow:established,to_server; content:"GET"; http_method; content:"/ur.php"; http_uri; content:"GET /ur.php "; depth:12; classtype:trojan-activity; sid:2012625; rev:3; metadata:created_at 2011_04_04, updated_at 2011_04_04;)

# 2012625
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Potential Lizamoon Client Request /ur.php"; flow:established,to_server; content:"GET"; http_method; content:"/ur.php"; http_uri; content:"GET /ur.php "; depth:12; classtype:trojan-activity; sid:2012625; rev:3; metadata:created_at 2011_04_04, updated_at 2011_04_04;)
` 

Name : **Potential Lizamoon Client Request /ur.php** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-04

Last modified date : 2011-04-04

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Paypal Phishing victim POSTing data"; flow:established,to_server; content:"POST"; http_method; content:"usr="; content:"&pwd="; content:"&name-on="; content:"&cu-on="; content:"&how2-on="; fast_pattern; classtype:bad-unknown; sid:2012630; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2011_04_05, updated_at 2016_07_01;)

# 2012630
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Paypal Phishing victim POSTing data"; flow:established,to_server; content:"POST"; http_method; content:"usr="; content:"&pwd="; content:"&name-on="; content:"&cu-on="; content:"&how2-on="; fast_pattern; classtype:bad-unknown; sid:2012630; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2011_04_05, updated_at 2016_07_01;)
` 

Name : **Paypal Phishing victim POSTing data** 

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

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-05

Last modified date : 2016-07-01

Rev version : 3

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET CURRENT_EVENTS Potential Paypal Phishing Form Attachment"; flow:established,to_server; content:"Content-Disposition|3A| attachment|3b|"; nocase; content:"Restore Your Account"; distance:0; nocase; content:"paypal"; distance:0; nocase; content:"form.php|22| method=|22|post|22|"; nocase; distance:0; classtype:bad-unknown; sid:2012632; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2011_04_05, updated_at 2016_07_01;)

# 2012632
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET CURRENT_EVENTS Potential Paypal Phishing Form Attachment"; flow:established,to_server; content:"Content-Disposition|3A| attachment|3b|"; nocase; content:"Restore Your Account"; distance:0; nocase; content:"paypal"; distance:0; nocase; content:"form.php|22| method=|22|post|22|"; nocase; distance:0; classtype:bad-unknown; sid:2012632; rev:3; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2011_04_05, updated_at 2016_07_01;)
` 

Name : **Potential Paypal Phishing Form Attachment** 

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

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-05

Last modified date : 2016-07-01

Rev version : 3

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET CURRENT_EVENTS Potential ACH Transaction Phishing Attachment"; flow:established,to_server; content:"ACH transaction"; nocase; content:".pdf.exe"; nocase; classtype:bad-unknown; sid:2012635; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2011_04_05, updated_at 2016_07_01;)

# 2012635
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET CURRENT_EVENTS Potential ACH Transaction Phishing Attachment"; flow:established,to_server; content:"ACH transaction"; nocase; content:".pdf.exe"; nocase; classtype:bad-unknown; sid:2012635; rev:2; metadata:attack_target Client_Endpoint, deployment Perimeter, tag Phishing, signature_severity Major, created_at 2011_04_05, updated_at 2016_07_01;)
` 

Name : **Potential ACH Transaction Phishing Attachment** 

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

Alert Classtype : social-engineering

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-05

Last modified date : 2016-07-01

Rev version : 2

Category : PHISHING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Java Exploit Attempt Request for hostile binary"; flow:established,to_server; content:"&|20|HTTP/1.1|0d 0a|User-A"; fast_pattern; content:".php?height="; http_uri; content:"|20|Java/"; http_header; pcre:"/\/[a-z0-9]{30,}\.php\?height=\d+&sid=\d+&width=[a-z0-9]+&/U"; classtype:trojan-activity; sid:2012644; rev:3; metadata:created_at 2011_04_06, updated_at 2011_04_06;)

# 2012644
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Java Exploit Attempt Request for hostile binary"; flow:established,to_server; content:"&|20|HTTP/1.1|0d 0a|User-A"; fast_pattern; content:".php?height="; http_uri; content:"|20|Java/"; http_header; pcre:"/\/[a-z0-9]{30,}\.php\?height=\d+&sid=\d+&width=[a-z0-9]+&/U"; classtype:trojan-activity; sid:2012644; rev:3; metadata:created_at 2011_04_06, updated_at 2011_04_06;)
` 

Name : **Java Exploit Attempt Request for hostile binary** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-06

Last modified date : 2011-04-06

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Malicious JAR olig"; flow:established,from_server; content:"|00 00|META-INF/PK|0a|"; fast_pattern; content:"|00|olig/"; classtype:trojan-activity; sid:2012646; rev:3; metadata:created_at 2011_04_06, updated_at 2011_04_06;)

# 2012646
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Malicious JAR olig"; flow:established,from_server; content:"|00 00|META-INF/PK|0a|"; fast_pattern; content:"|00|olig/"; classtype:trojan-activity; sid:2012646; rev:3; metadata:created_at 2011_04_06, updated_at 2011_04_06;)
` 

Name : **Malicious JAR olig** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-06

Last modified date : 2011-04-06

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Pack Binary Load Request"; flow:established,to_server; content:".php?sex="; nocase; http_uri; content:"&children="; nocase; http_uri; content:"&userid="; nocase; http_uri; pcre:"/\.php\?sex=\d+&children=\d+&userid=/U"; classtype:trojan-activity; sid:2012687; rev:2; metadata:created_at 2011_04_13, updated_at 2011_04_13;)

# 2012687
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Pack Binary Load Request"; flow:established,to_server; content:".php?sex="; nocase; http_uri; content:"&children="; nocase; http_uri; content:"&userid="; nocase; http_uri; pcre:"/\.php\?sex=\d+&children=\d+&userid=/U"; classtype:trojan-activity; sid:2012687; rev:2; metadata:created_at 2011_04_13, updated_at 2011_04_13;)
` 

Name : **Unknown Exploit Pack Binary Load Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-13

Last modified date : 2011-04-13

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Adobe Flash Unicode SWF File Embedded in Office File Caution - Could be Hostile"; flow:established,from_server; flowbits:isset,OLE.CompoundFile; content:"S|00|W|00|F|00|"; reference:url,blogs.adobe.com/asset/2011/03/background-on-apsa11-01-patch-schedule.html; reference:url,bugix-security.blogspot.com/2011/03/cve-2011-0609-adobe-flash-player.html; reference:bid,46860; reference:cve,2011-0609; reference:url,www.adobe.com/support/security/advisories/apsa11-02.html; reference:cve,2011-0611; classtype:attempted-user; sid:2012622; rev:5; metadata:created_at 2011_03_31, updated_at 2011_03_31;)

# 2012622
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Adobe Flash Unicode SWF File Embedded in Office File Caution - Could be Hostile"; flow:established,from_server; flowbits:isset,OLE.CompoundFile; content:"S|00|W|00|F|00|"; reference:url,blogs.adobe.com/asset/2011/03/background-on-apsa11-01-patch-schedule.html; reference:url,bugix-security.blogspot.com/2011/03/cve-2011-0609-adobe-flash-player.html; reference:bid,46860; reference:cve,2011-0609; reference:url,www.adobe.com/support/security/advisories/apsa11-02.html; reference:cve,2011-0611; classtype:attempted-user; sid:2012622; rev:5; metadata:created_at 2011_03_31, updated_at 2011_03_31;)
` 

Name : **Adobe Flash Unicode SWF File Embedded in Office File Caution - Could be Hostile** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,blogs.adobe.com/asset/2011/03/background-on-apsa11-01-patch-schedule.html|url,bugix-security.blogspot.com/2011/03/cve-2011-0609-adobe-flash-player.html|bid,46860|cve,2011-0609|url,www.adobe.com/support/security/advisories/apsa11-02.html|cve,2011-0611

CVE reference : Not defined

Creation date : 2011-03-31

Last modified date : 2011-03-31

Rev version : 5

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Likely Redirector to Exploit Page /in/rdrct/rckt/?"; flow:established,to_server; content:"/in/rdrct/rckt/?"; http_uri; classtype:attempted-user; sid:2012731; rev:2; metadata:created_at 2011_04_28, updated_at 2011_04_28;)

# 2012731
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Likely Redirector to Exploit Page /in/rdrct/rckt/?"; flow:established,to_server; content:"/in/rdrct/rckt/?"; http_uri; classtype:attempted-user; sid:2012731; rev:2; metadata:created_at 2011_04_28, updated_at 2011_04_28;)
` 

Name : **Likely Redirector to Exploit Page /in/rdrct/rckt/?** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-28

Last modified date : 2011-04-28

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown .ru Exploit Redirect Page"; flow:established,to_server; content:"people/?"; http_uri; content:"&top="; http_uri; content:".ru|0d 0a|"; http_header; classtype:bad-unknown; sid:2012732; rev:2; metadata:created_at 2011_04_28, updated_at 2011_04_28;)

# 2012732
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown .ru Exploit Redirect Page"; flow:established,to_server; content:"people/?"; http_uri; content:"&top="; http_uri; content:".ru|0d 0a|"; http_header; classtype:bad-unknown; sid:2012732; rev:2; metadata:created_at 2011_04_28, updated_at 2011_04_28;)
` 

Name : **Unknown .ru Exploit Redirect Page** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-04-28

Last modified date : 2011-04-28

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Eleonore Exploit Pack exemple.com Request"; flow:established,to_server; content:"/exemple.com/"; nocase; http_uri; classtype:trojan-activity; sid:2012940; rev:2; metadata:created_at 2011_06_07, updated_at 2011_06_07;)

# 2012940
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Eleonore Exploit Pack exemple.com Request"; flow:established,to_server; content:"/exemple.com/"; nocase; http_uri; classtype:trojan-activity; sid:2012940; rev:2; metadata:created_at 2011_06_07, updated_at 2011_06_07;)
` 

Name : **Eleonore Exploit Pack exemple.com Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-07

Last modified date : 2011-06-07

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Java/PDF Exploit kit from /Home/games/ initial landing"; flow:established,to_server; content:"/Home/games/2fdp.php?f="; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013025; rev:2; metadata:created_at 2011_06_13, updated_at 2011_06_13;)

# 2013025
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Java/PDF Exploit kit from /Home/games/ initial landing"; flow:established,to_server; content:"/Home/games/2fdp.php?f="; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013025; rev:2; metadata:created_at 2011_06_13, updated_at 2011_06_13;)
` 

Name : **Java/PDF Exploit kit from /Home/games/ initial landing** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-13

Last modified date : 2011-06-13

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Exploit kit mario.jar"; flow:established,to_server; content:"pack200"; http_header; content:" Java/"; http_header; content:"/mario.jar"; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013024; rev:3; metadata:created_at 2011_06_13, updated_at 2011_06_13;)

# 2013024
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Exploit kit mario.jar"; flow:established,to_server; content:"pack200"; http_header; content:" Java/"; http_header; content:"/mario.jar"; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013024; rev:3; metadata:created_at 2011_06_13, updated_at 2011_06_13;)
` 

Name : **Exploit kit mario.jar** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-13

Last modified date : 2011-06-13

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Java/PDF Exploit kit initial landing"; flow:established,to_server; content:"/2fdp.php?f="; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013027; rev:3; metadata:created_at 2011_06_13, updated_at 2011_06_13;)

# 2013027
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Java/PDF Exploit kit initial landing"; flow:established,to_server; content:"/2fdp.php?f="; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013027; rev:3; metadata:created_at 2011_06_13, updated_at 2011_06_13;)
` 

Name : **Java/PDF Exploit kit initial landing** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-13

Last modified date : 2011-06-13

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Fake Shipping Invoice Request to JPG.exe Executable"; flow:established,to_server; content:"/invoice"; nocase; http_uri; content:".JPG.exe"; nocase; fast_pattern; classtype:trojan-activity; sid:2013048; rev:4; metadata:created_at 2011_06_16, updated_at 2011_06_16;)

# 2013048
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Fake Shipping Invoice Request to JPG.exe Executable"; flow:established,to_server; content:"/invoice"; nocase; http_uri; content:".JPG.exe"; nocase; fast_pattern; classtype:trojan-activity; sid:2013048; rev:4; metadata:created_at 2011_06_16, updated_at 2011_06_16;)
` 

Name : **Fake Shipping Invoice Request to JPG.exe Executable** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-16

Last modified date : 2011-06-16

Rev version : 4

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Sidename.js Injected Script Served by Local WebServer"; flow:established,from_server; content:"/sidename.js\"></script>"; nocase; fast_pattern:only; reference:url,blog.armorize.com/2011/06/mass-meshing-injection-sidenamejs.html; classtype:web-application-attack; sid:2013061; rev:3; metadata:created_at 2011_06_17, updated_at 2011_06_17;)

# 2013061
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Sidename.js Injected Script Served by Local WebServer"; flow:established,from_server; content:"/sidename.js\"></script>"; nocase; fast_pattern:only; reference:url,blog.armorize.com/2011/06/mass-meshing-injection-sidenamejs.html; classtype:web-application-attack; sid:2013061; rev:3; metadata:created_at 2011_06_17, updated_at 2011_06_17;)
` 

Name : **Sidename.js Injected Script Served by Local WebServer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,blog.armorize.com/2011/06/mass-meshing-injection-sidenamejs.html

CVE reference : Not defined

Creation date : 2011-06-17

Last modified date : 2011-06-17

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Java Exploit Attempt applet via file URI setAttribute"; flow:established,from_server; content:"setAttribute("; content:"C|3a 5c 5c|Progra"; fast_pattern; nocase; distance:0; content:"java"; nocase; distance:0; content:"jre6"; nocase; distance:0; content:"lib"; nocase; distance:0; content:"ext"; nocase; distance:0; reference:url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/; reference:cve,CVE-2010-4452; classtype:trojan-activity; sid:2013066; rev:3; metadata:created_at 2011_06_17, updated_at 2011_06_17;)

# 2013066
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Java Exploit Attempt applet via file URI setAttribute"; flow:established,from_server; content:"setAttribute("; content:"C|3a 5c 5c|Progra"; fast_pattern; nocase; distance:0; content:"java"; nocase; distance:0; content:"jre6"; nocase; distance:0; content:"lib"; nocase; distance:0; content:"ext"; nocase; distance:0; reference:url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/; reference:cve,CVE-2010-4452; classtype:trojan-activity; sid:2013066; rev:3; metadata:created_at 2011_06_17, updated_at 2011_06_17;)
` 

Name : **Java Exploit Attempt applet via file URI setAttribute** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/|cve,CVE-2010-4452

CVE reference : Not defined

Creation date : 2011-06-17

Last modified date : 2011-06-17

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Driveby Exploit Kit Browser Progress Checkin - Binary Likely Previously Downloaded"; flow:established,to_server; content:"/?"; http_uri; content:!" Java/"; http_header; pcre:"/\/\?[a-f0-9]{64}\;\d\;\d/U"; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013098; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_06_22, updated_at 2016_07_01;)

# 2013098
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Driveby Exploit Kit Browser Progress Checkin - Binary Likely Previously Downloaded"; flow:established,to_server; content:"/?"; http_uri; content:!" Java/"; http_header; pcre:"/\/\?[a-f0-9]{64}\;\d\;\d/U"; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013098; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_06_22, updated_at 2016_07_01;)
` 

Name : **Driveby Exploit Kit Browser Progress Checkin - Binary Likely Previously Downloaded** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-22

Last modified date : 2016-07-01

Rev version : 3

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Possible CVE-2011-2110 Flash Exploit Attempt Embedded in Web Page"; flow:established,to_client; content:"<param name="; nocase; content:"value="; nocase; distance:0; content:"|2E|swf?info="; fast_pattern; nocase; distance:0; pcre:"/value\x22[^\x22]*\x2Eswf\x3finfo\x3D/smi"; reference:url,stopmalvertising.com/malware-reports/all-ur-swf-bel0ng-2-us-analysis-of-cve-2011-2110.html; reference:bid,48268; reference:cve,2011-2110; classtype:attempted-user; sid:2013137; rev:3; metadata:created_at 2011_06_30, updated_at 2011_06_30;)

# 2013137
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Possible CVE-2011-2110 Flash Exploit Attempt Embedded in Web Page"; flow:established,to_client; content:"<param name="; nocase; content:"value="; nocase; distance:0; content:"|2E|swf?info="; fast_pattern; nocase; distance:0; pcre:"/value\x22[^\x22]*\x2Eswf\x3finfo\x3D/smi"; reference:url,stopmalvertising.com/malware-reports/all-ur-swf-bel0ng-2-us-analysis-of-cve-2011-2110.html; reference:bid,48268; reference:cve,2011-2110; classtype:attempted-user; sid:2013137; rev:3; metadata:created_at 2011_06_30, updated_at 2011_06_30;)
` 

Name : **Possible CVE-2011-2110 Flash Exploit Attempt Embedded in Web Page** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,stopmalvertising.com/malware-reports/all-ur-swf-bel0ng-2-us-analysis-of-cve-2011-2110.html|bid,48268|cve,2011-2110

CVE reference : Not defined

Creation date : 2011-06-30

Last modified date : 2011-06-30

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Possible CVE-2011-2110 Flash Exploit Attempt"; flow:established,to_server; content:"GET /"; depth:5; content:".swf?info=02"; http_uri; reference:url,www.shadowserver.org/wiki/pmwiki.php/Calendar/20110617; classtype:trojan-activity; sid:2013065; rev:4; metadata:created_at 2011_06_17, updated_at 2011_06_17;)

# 2013065
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Possible CVE-2011-2110 Flash Exploit Attempt"; flow:established,to_server; content:"GET /"; depth:5; content:".swf?info=02"; http_uri; reference:url,www.shadowserver.org/wiki/pmwiki.php/Calendar/20110617; classtype:trojan-activity; sid:2013065; rev:4; metadata:created_at 2011_06_17, updated_at 2011_06_17;)
` 

Name : **Possible CVE-2011-2110 Flash Exploit Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,www.shadowserver.org/wiki/pmwiki.php/Calendar/20110617

CVE reference : Not defined

Creation date : 2011-06-17

Last modified date : 2011-06-17

Rev version : 4

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS cssminibar.js Injected Script Served by Local WebServer"; flow:established,from_server; content:"cssminibar.js|22|></script>"; nocase; fast_pattern:only; reference:url,blog.armorize.com/2011/06/mass-meshing-injection-sidenamejs.html; classtype:web-application-attack; sid:2013192; rev:2; metadata:created_at 2011_07_05, updated_at 2011_07_05;)

# 2013192
`#alert http $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS cssminibar.js Injected Script Served by Local WebServer"; flow:established,from_server; content:"cssminibar.js|22|></script>"; nocase; fast_pattern:only; reference:url,blog.armorize.com/2011/06/mass-meshing-injection-sidenamejs.html; classtype:web-application-attack; sid:2013192; rev:2; metadata:created_at 2011_07_05, updated_at 2011_07_05;)
` 

Name : **cssminibar.js Injected Script Served by Local WebServer** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,blog.armorize.com/2011/06/mass-meshing-injection-sidenamejs.html

CVE reference : Not defined

Creation date : 2011-07-05

Last modified date : 2011-07-05

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Known Injected Credit Card Fraud Malvertisement Script"; flow:established,to_client; content:"|3C|script|3E|ba|28 27|Windows.class|27 2C 27|Windows.jar|27 29 3B 3C 2F|script|3E|"; nocase; reference:url,blogs.paretologic.com/malwarediaries/index.php/2011/07/06/stolen-credit-cards-site-injected-with-malware/; classtype:misc-activity; sid:2013244; rev:2; metadata:created_at 2011_07_11, updated_at 2011_07_11;)

# 2013244
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Known Injected Credit Card Fraud Malvertisement Script"; flow:established,to_client; content:"|3C|script|3E|ba|28 27|Windows.class|27 2C 27|Windows.jar|27 29 3B 3C 2F|script|3E|"; nocase; reference:url,blogs.paretologic.com/malwarediaries/index.php/2011/07/06/stolen-credit-cards-site-injected-with-malware/; classtype:misc-activity; sid:2013244; rev:2; metadata:created_at 2011_07_11, updated_at 2011_07_11;)
` 

Name : **Known Injected Credit Card Fraud Malvertisement Script** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : url,blogs.paretologic.com/malwarediaries/index.php/2011/07/06/stolen-credit-cards-site-injected-with-malware/

CVE reference : Not defined

Creation date : 2011-07-11

Last modified date : 2011-07-11

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - flickr.com.* "; content:"|05|flickr|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013353; rev:3; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)

# 2013353
`#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - flickr.com.* "; content:"|05|flickr|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013353; rev:3; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)
` 

Name : **Wordpress possible Malicious DNS-Requests - flickr.com.* ** 

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

Alert Classtype : web-application-attack

URL reference : url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/|url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability|url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29

CVE reference : Not defined

Creation date : 2011-08-04

Last modified date : 2016-07-01

Rev version : 3

Category : CURRENT_EVENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - picasa.com.* "; content:"|06|picasa|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013354; rev:3; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)

# 2013354
`#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - picasa.com.* "; content:"|06|picasa|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013354; rev:3; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)
` 

Name : **Wordpress possible Malicious DNS-Requests - picasa.com.* ** 

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

Alert Classtype : web-application-attack

URL reference : url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/|url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability|url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29

CVE reference : Not defined

Creation date : 2011-08-04

Last modified date : 2016-07-01

Rev version : 3

Category : CURRENT_EVENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - blogger.com.* "; content:"|07|blogger|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013355; rev:3; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)

# 2013355
`#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - blogger.com.* "; content:"|07|blogger|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013355; rev:3; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)
` 

Name : **Wordpress possible Malicious DNS-Requests - blogger.com.* ** 

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

Alert Classtype : web-application-attack

URL reference : url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/|url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability|url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29

CVE reference : Not defined

Creation date : 2011-08-04

Last modified date : 2016-07-01

Rev version : 3

Category : CURRENT_EVENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - wordpress.com.* "; content:"|09|wordpress|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013357; rev:1; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)

# 2013357
`#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - wordpress.com.* "; content:"|09|wordpress|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013357; rev:1; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)
` 

Name : **Wordpress possible Malicious DNS-Requests - wordpress.com.* ** 

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

Alert Classtype : web-application-attack

URL reference : url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/|url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability|url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29

CVE reference : Not defined

Creation date : 2011-08-04

Last modified date : 2016-07-01

Rev version : 1

Category : CURRENT_EVENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - img.youtube.com.* "; content:"|03|img|07|youtube|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013358; rev:2; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)

# 2013358
`#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - img.youtube.com.* "; content:"|03|img|07|youtube|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013358; rev:2; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)
` 

Name : **Wordpress possible Malicious DNS-Requests - img.youtube.com.* ** 

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

Alert Classtype : web-application-attack

URL reference : url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/|url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability|url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29

CVE reference : Not defined

Creation date : 2011-08-04

Last modified date : 2016-07-01

Rev version : 2

Category : CURRENT_EVENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - upload.wikimedia.com.* "; content:"|06|upload|09|wikimedia|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013359; rev:2; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)

# 2013359
`#alert udp !$DNS_SERVERS any -> $DNS_SERVERS 53 (msg:"ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - upload.wikimedia.com.* "; content:"|06|upload|09|wikimedia|03|com"; nocase; content:!"|00|"; within:1; reference:url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/; reference:url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability; reference:url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29; classtype:web-application-attack; sid:2013359; rev:2; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_04, updated_at 2016_07_01;)
` 

Name : **Wordpress possible Malicious DNS-Requests - upload.wikimedia.com.* ** 

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

Alert Classtype : web-application-attack

URL reference : url,markmaunder.com/2011/zero-day-vulnerability-in-many-wordpress-themes/|url,www.us-cert.gov/current/index.html#wordpress_themes_vulnerability|url,blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SucuriSecurity+%28Sucuri+Security%29

CVE reference : Not defined

Creation date : 2011-08-04

Last modified date : 2016-07-01

Rev version : 2

Category : CURRENT_EVENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Obfuscated Javascript Often Used in Drivebys"; flow:established,from_server; content:"Content-Type|3a 20|text/html"; content:"|0d 0a|<html><body><div|20|"; fast_pattern; within:500; pcre:"/\x7b?(visibility\x3ahidden|display\x3anone)\x3b?\x7d?\x22><div>\d{16}/R"; classtype:trojan-activity; sid:2013237; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_07_08, updated_at 2016_07_01;)

# 2013237
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Obfuscated Javascript Often Used in Drivebys"; flow:established,from_server; content:"Content-Type|3a 20|text/html"; content:"|0d 0a|<html><body><div|20|"; fast_pattern; within:500; pcre:"/\x7b?(visibility\x3ahidden|display\x3anone)\x3b?\x7d?\x22><div>\d{16}/R"; classtype:trojan-activity; sid:2013237; rev:5; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_07_08, updated_at 2016_07_01;)
` 

Name : **Obfuscated Javascript Often Used in Drivebys** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-07-08

Last modified date : 2016-07-01

Rev version : 5

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Malicious 1px iframe related to Mass Wordpress Injections"; flow:established,from_server; content:"/?go=1|22 20|width=|22|1|22 20|height=|22|1|22|></iframe>"; fast_pattern; content:"<html"; nocase; distance:0; classtype:bad-unknown; sid:2013380; rev:2; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_10, updated_at 2016_07_01;)

# 2013380
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Malicious 1px iframe related to Mass Wordpress Injections"; flow:established,from_server; content:"/?go=1|22 20|width=|22|1|22 20|height=|22|1|22|></iframe>"; fast_pattern; content:"<html"; nocase; distance:0; classtype:bad-unknown; sid:2013380; rev:2; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2011_08_10, updated_at 2016_07_01;)
` 

Name : **Malicious 1px iframe related to Mass Wordpress Injections** 

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

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-08-10

Last modified date : 2016-07-01

Rev version : 2

Category : CURRENT_EVENTS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Java Exploit Attempt applet via file URI param"; flow:established,from_server; content:"applet"; nocase; content:"file|3a|C|3a 5c|Progra"; fast_pattern; nocase; distance:0; content:"java"; nocase; distance:0; content:"jre6"; nocase; distance:0; content:"lib"; nocase; distance:0; content:"ext"; nocase; distance:0; reference:url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/; reference:cve,CVE-2010-4452; classtype:trojan-activity; sid:2012884; rev:3; metadata:created_at 2011_05_27, updated_at 2011_05_27;)

# 2012884
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Java Exploit Attempt applet via file URI param"; flow:established,from_server; content:"applet"; nocase; content:"file|3a|C|3a 5c|Progra"; fast_pattern; nocase; distance:0; content:"java"; nocase; distance:0; content:"jre6"; nocase; distance:0; content:"lib"; nocase; distance:0; content:"ext"; nocase; distance:0; reference:url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/; reference:cve,CVE-2010-4452; classtype:trojan-activity; sid:2012884; rev:3; metadata:created_at 2011_05_27, updated_at 2011_05_27;)
` 

Name : **Java Exploit Attempt applet via file URI param** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/|cve,CVE-2010-4452

CVE reference : Not defined

Creation date : 2011-05-27

Last modified date : 2011-05-27

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Exploit kit worms.jar"; flow:established,to_server; content:"pack200"; http_header; content:" Java/"; http_header; content:"/worms.jar"; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013661; rev:2; metadata:created_at 2011_09_15, updated_at 2011_09_15;)

# 2013661
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Exploit kit worms.jar"; flow:established,to_server; content:"pack200"; http_header; content:" Java/"; http_header; content:"/worms.jar"; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013661; rev:2; metadata:created_at 2011_09_15, updated_at 2011_09_15;)
` 

Name : **Exploit kit worms.jar** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-15

Last modified date : 2011-09-15

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Driveby Generic Java Exploit Attempt"; flow:established,to_client; content:" codebase=|22|C|3a 5c|Program Files|5c|java|5c|jre6|5c|lib|5c|ext|22| code="; nocase; reference:url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/; reference:cve,CVE-2010-4452; classtype:trojan-activity; sid:2013551; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_09_09, updated_at 2016_07_01;)

# 2013551
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Driveby Generic Java Exploit Attempt"; flow:established,to_client; content:" codebase=|22|C|3a 5c|Program Files|5c|java|5c|jre6|5c|lib|5c|ext|22| code="; nocase; reference:url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/; reference:cve,CVE-2010-4452; classtype:trojan-activity; sid:2013551; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_09_09, updated_at 2016_07_01;)
` 

Name : **Driveby Generic Java Exploit Attempt** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/|cve,CVE-2010-4452

CVE reference : Not defined

Creation date : 2011-09-09

Last modified date : 2016-07-01

Rev version : 3

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Driveby Generic Java Exploit Attempt 2"; flow:established,to_client; content:" codebase=|22|C|3a 5c|Program Files (x86)|5c|java|5c|jre6|5c|lib|5c|ext|22| code="; nocase; reference:url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/; reference:cve,CVE-2010-4452; classtype:trojan-activity; sid:2013552; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_09_09, updated_at 2016_07_01;)

# 2013552
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Driveby Generic Java Exploit Attempt 2"; flow:established,to_client; content:" codebase=|22|C|3a 5c|Program Files (x86)|5c|java|5c|jre6|5c|lib|5c|ext|22| code="; nocase; reference:url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/; reference:cve,CVE-2010-4452; classtype:trojan-activity; sid:2013552; rev:3; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_09_09, updated_at 2016_07_01;)
` 

Name : **Driveby Generic Java Exploit Attempt 2** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/|cve,CVE-2010-4452

CVE reference : Not defined

Creation date : 2011-09-09

Last modified date : 2016-07-01

Rev version : 3

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Java Exploit Kit x.jar?o="; flow:established,to_server; content:"/x.jar?o="; http_uri; content:"|20|Java/"; http_header; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013696; rev:3; metadata:created_at 2011_09_27, updated_at 2011_09_27;)

# 2013696
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Java Exploit Kit x.jar?o="; flow:established,to_server; content:"/x.jar?o="; http_uri; content:"|20|Java/"; http_header; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013696; rev:3; metadata:created_at 2011_09_27, updated_at 2011_09_27;)
` 

Name : **Unknown Java Exploit Kit x.jar?o=** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-27

Last modified date : 2011-09-27

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Java Exploit Kit lo.class"; flow:established,to_server; content:"/lo.class"; http_uri; content:"|20|Java/"; http_header; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013697; rev:3; metadata:created_at 2011_09_27, updated_at 2011_09_27;)

# 2013697
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Java Exploit Kit lo.class"; flow:established,to_server; content:"/lo.class"; http_uri; content:"|20|Java/"; http_header; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013697; rev:3; metadata:created_at 2011_09_27, updated_at 2011_09_27;)
` 

Name : **Unknown Java Exploit Kit lo.class** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-27

Last modified date : 2011-09-27

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Java Exploit Kit lo2.jar"; flow:established,to_server; content:"/lo2.jar"; http_uri; content:"|20|Java/"; http_header; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013698; rev:3; metadata:created_at 2011_09_27, updated_at 2011_09_27;)

# 2013698
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Java Exploit Kit lo2.jar"; flow:established,to_server; content:"/lo2.jar"; http_uri; content:"|20|Java/"; http_header; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013698; rev:3; metadata:created_at 2011_09_27, updated_at 2011_09_27;)
` 

Name : **Unknown Java Exploit Kit lo2.jar** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-27

Last modified date : 2011-09-27

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Lilupophilupop Injected Script Being Served to Client"; flow:established,to_client; content:"|3C|script src=|22|http|3A|//lilupophilupop.com/sl.php|22|>|3C 2F|script>"; nocase; classtype:bad-unknown; sid:2013978; rev:3; metadata:created_at 2011_12_02, updated_at 2011_12_02;)

# 2013978
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Lilupophilupop Injected Script Being Served to Client"; flow:established,to_client; content:"|3C|script src=|22|http|3A|//lilupophilupop.com/sl.php|22|>|3C 2F|script>"; nocase; classtype:bad-unknown; sid:2013978; rev:3; metadata:created_at 2011_12_02, updated_at 2011_12_02;)
` 

Name : **Lilupophilupop Injected Script Being Served to Client** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-02

Last modified date : 2011-12-02

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Lilupophilupop Injected Script Being Served from Local Server"; flow:established,from_server; content:"|3C|script src=|22|http|3A|//lilupophilupop.com/sl.php|22|>|3C 2F|script>"; nocase; classtype:bad-unknown; sid:2013979; rev:3; metadata:created_at 2011_12_02, updated_at 2011_12_02;)

# 2013979
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Lilupophilupop Injected Script Being Served from Local Server"; flow:established,from_server; content:"|3C|script src=|22|http|3A|//lilupophilupop.com/sl.php|22|>|3C 2F|script>"; nocase; classtype:bad-unknown; sid:2013979; rev:3; metadata:created_at 2011_12_02, updated_at 2011_12_02;)
` 

Name : **Lilupophilupop Injected Script Being Served from Local Server** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-02

Last modified date : 2011-12-02

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Likely Generic Java Exploit Attempt Request for Java to decimal host"; flow:established,to_server; content:" Java/1"; http_header; pcre:"/Host\x3a \d{8,10}(\x0d\x0a|\x3a\d{1,5}\x0d\x0a)/H"; reference:url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/; reference:cve,CVE-2010-4452; classtype:trojan-activity; sid:2013487; rev:5; metadata:created_at 2011_08_30, updated_at 2011_08_30;)

# 2013487
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Likely Generic Java Exploit Attempt Request for Java to decimal host"; flow:established,to_server; content:" Java/1"; http_header; pcre:"/Host\x3a \d{8,10}(\x0d\x0a|\x3a\d{1,5}\x0d\x0a)/H"; reference:url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/; reference:cve,CVE-2010-4452; classtype:trojan-activity; sid:2013487; rev:5; metadata:created_at 2011_08_30, updated_at 2011_08_30;)
` 

Name : **Likely Generic Java Exploit Attempt Request for Java to decimal host** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,fhoguin.com/2011/03/oracle-java-unsigned-applet-applet2classloader-remote-code-execution-vulnerability-zdi-11-084-explained/|cve,CVE-2010-4452

CVE reference : Not defined

Creation date : 2011-08-30

Last modified date : 2011-08-30

Rev version : 5

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Probable Scalaxy exploit kit Java or PDF exploit request"; flow:established,to_server; content:"/"; http_uri; offset:2; depth:3; urilen:35; pcre:"/\/[a-z]\/[0-9a-f]{32}$/U"; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2014025; rev:1; metadata:created_at 2011_12_12, updated_at 2011_12_12;)

# 2014025
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Probable Scalaxy exploit kit Java or PDF exploit request"; flow:established,to_server; content:"/"; http_uri; offset:2; depth:3; urilen:35; pcre:"/\/[a-z]\/[0-9a-f]{32}$/U"; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2014025; rev:1; metadata:created_at 2011_12_12, updated_at 2011_12_12;)
` 

Name : **Probable Scalaxy exploit kit Java or PDF exploit request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-12

Last modified date : 2011-12-12

Rev version : 1

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Obfuscated Base64 in Javascript probably Scalaxy exploit kit"; flow:established,from_server; content:!"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; content:"|2b 2f 3d 22 3b|"; fast_pattern; content:"<<18|7c|"; within:500; content:"<<12|7c|"; within:13; content:"<<6|7c|"; within:13; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2014027; rev:2; metadata:created_at 2011_12_12, updated_at 2011_12_12;)

# 2014027
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Obfuscated Base64 in Javascript probably Scalaxy exploit kit"; flow:established,from_server; content:!"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; content:"|2b 2f 3d 22 3b|"; fast_pattern; content:"<<18|7c|"; within:500; content:"<<12|7c|"; within:13; content:"<<6|7c|"; within:13; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2014027; rev:2; metadata:created_at 2011_12_12, updated_at 2011_12_12;)
` 

Name : **Obfuscated Base64 in Javascript probably Scalaxy exploit kit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-12

Last modified date : 2011-12-12

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested com.class"; flow:established,to_server; content:" Java/1"; http_header; content:"/com.class"; http_uri; classtype:trojan-activity; sid:2014031; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_12_19, updated_at 2016_07_01;)

# 2014031
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested com.class"; flow:established,to_server; content:" Java/1"; http_header; content:"/com.class"; http_uri; classtype:trojan-activity; sid:2014031; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_12_19, updated_at 2016_07_01;)
` 

Name : **DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested com.class** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-19

Last modified date : 2016-07-01

Rev version : 2

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested org.class"; flow:established,to_server; content:" Java/1"; http_header; content:"/org.class"; http_uri; classtype:trojan-activity; sid:2014032; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_12_19, updated_at 2016_07_01;)

# 2014032
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested org.class"; flow:established,to_server; content:" Java/1"; http_header; content:"/org.class"; http_uri; classtype:trojan-activity; sid:2014032; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_12_19, updated_at 2016_07_01;)
` 

Name : **DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested org.class** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-19

Last modified date : 2016-07-01

Rev version : 2

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested edu.class"; flow:established,to_server; content:" Java/1"; http_header; content:"/edu.class"; http_uri; classtype:trojan-activity; sid:2014033; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_12_19, updated_at 2016_07_01;)

# 2014033
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested edu.class"; flow:established,to_server; content:" Java/1"; http_header; content:"/edu.class"; http_uri; classtype:trojan-activity; sid:2014033; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_12_19, updated_at 2016_07_01;)
` 

Name : **DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested edu.class** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-19

Last modified date : 2016-07-01

Rev version : 2

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested net.class"; flow:established,to_server; content:" Java/1"; http_header; content:"/net.class"; http_uri; classtype:trojan-activity; sid:2014034; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_12_19, updated_at 2016_07_01;)

# 2014034
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested net.class"; flow:established,to_server; content:" Java/1"; http_header; content:"/net.class"; http_uri; classtype:trojan-activity; sid:2014034; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2011_12_19, updated_at 2016_07_01;)
` 

Name : **DRIVEBY Generic Java Rhino Scripting Engine Exploit Previously Requested net.class** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-19

Last modified date : 2016-07-01

Rev version : 2

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS User-Agent used in Injection Attempts"; flow:established,to_server; content:"User-Agent|3a| MOT-MPx220/1.400 Mozilla/4.0"; http_header; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2011-December/016882.html; classtype:trojan-activity; sid:2014054; rev:2; metadata:created_at 2011_12_30, updated_at 2011_12_30;)

# 2014054
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS User-Agent used in Injection Attempts"; flow:established,to_server; content:"User-Agent|3a| MOT-MPx220/1.400 Mozilla/4.0"; http_header; reference:url,lists.emergingthreats.net/pipermail/emerging-sigs/2011-December/016882.html; classtype:trojan-activity; sid:2014054; rev:2; metadata:created_at 2011_12_30, updated_at 2011_12_30;)
` 

Name : **User-Agent used in Injection Attempts** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : url,lists.emergingthreats.net/pipermail/emerging-sigs/2011-December/016882.html

CVE reference : Not defined

Creation date : 2011-12-30

Last modified date : 2011-12-30

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Download of Microsft Office File From Russian Content-Language Website"; flow:established,to_client; content:"Content-Language|3A| ru"; nocase; content:"|D0 CF 11 E0 A1 B1 1A E1|"; classtype:trojan-activity; sid:2012525; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)

# 2012525
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Download of Microsft Office File From Russian Content-Language Website"; flow:established,to_client; content:"Content-Language|3A| ru"; nocase; content:"|D0 CF 11 E0 A1 B1 1A E1|"; classtype:trojan-activity; sid:2012525; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)
` 

Name : **Download of Microsft Office File From Russian Content-Language Website** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-21

Last modified date : 2011-03-21

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Download of Microsoft Office File From Chinese Content-Language Website"; flow:established,to_client; content:"Content-Language|3A| zh-cn"; nocase; content:"|D0 CF 11 E0 A1 B1 1A E1|"; classtype:trojan-activity; sid:2012526; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)

# 2012526
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Download of Microsoft Office File From Chinese Content-Language Website"; flow:established,to_client; content:"Content-Language|3A| zh-cn"; nocase; content:"|D0 CF 11 E0 A1 B1 1A E1|"; classtype:trojan-activity; sid:2012526; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)
` 

Name : **Download of Microsoft Office File From Chinese Content-Language Website** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-21

Last modified date : 2011-03-21

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Download of PDF File From Russian Content-Language Website"; flow:established,to_client; content:"Content-Language|3A| ru"; nocase; content:"%PDF-"; classtype:trojan-activity; sid:2012527; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)

# 2012527
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Download of PDF File From Russian Content-Language Website"; flow:established,to_client; content:"Content-Language|3A| ru"; nocase; content:"%PDF-"; classtype:trojan-activity; sid:2012527; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)
` 

Name : **Download of PDF File From Russian Content-Language Website** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-21

Last modified date : 2011-03-21

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Download of PDF File From Chinese Content-Language Website"; flow:established,to_client; content:"Content-Language|3A| zh-cn"; nocase; content:"%PDF-"; classtype:trojan-activity; sid:2012528; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)

# 2012528
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Download of PDF File From Chinese Content-Language Website"; flow:established,to_client; content:"Content-Language|3A| zh-cn"; nocase; content:"%PDF-"; classtype:trojan-activity; sid:2012528; rev:3; metadata:created_at 2011_03_21, updated_at 2011_03_21;)
` 

Name : **Download of PDF File From Chinese Content-Language Website** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-03-21

Last modified date : 2011-03-21

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Saturn Exploit Kit binary download request"; flow:established,to_server; content:"/dl/"; depth:4; http_uri; fast_pattern; content:".php?"; http_uri; pcre:"/\/dl\/\w{1,4}\.php\?[0-9]$/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013775; rev:2; metadata:created_at 2011_10_13, updated_at 2011_10_13;)

# 2013775
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Saturn Exploit Kit binary download request"; flow:established,to_server; content:"/dl/"; depth:4; http_uri; fast_pattern; content:".php?"; http_uri; pcre:"/\/dl\/\w{1,4}\.php\?[0-9]$/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013775; rev:2; metadata:created_at 2011_10_13, updated_at 2011_10_13;)
` 

Name : **Saturn Exploit Kit binary download request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-10-13

Last modified date : 2011-10-13

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Saturn Exploit Kit probable Java MIDI exploit request"; flow:established,to_server; content:"/dl/jsm.php"; depth:14; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013777; rev:2; metadata:created_at 2011_10_13, updated_at 2011_10_13;)

# 2013777
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Saturn Exploit Kit probable Java MIDI exploit request"; flow:established,to_server; content:"/dl/jsm.php"; depth:14; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013777; rev:2; metadata:created_at 2011_10_13, updated_at 2011_10_13;)
` 

Name : **Saturn Exploit Kit probable Java MIDI exploit request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-10-13

Last modified date : 2011-10-13

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY SEO Exploit Kit request for PDF exploit"; flow:established,to_server; content:"POST"; http_method; content:"id="; content:"|25 32 36|np"; distance:32; within:5; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011348; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2010_09_28, updated_at 2016_07_01;)

# 2011348
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY SEO Exploit Kit request for PDF exploit"; flow:established,to_server; content:"POST"; http_method; content:"id="; content:"|25 32 36|np"; distance:32; within:5; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011348; rev:4; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2010_09_28, updated_at 2016_07_01;)
` 

Name : **DRIVEBY SEO Exploit Kit request for PDF exploit** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2016-07-01

Rev version : 4

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS SEO Exploit Kit - client exploited"; flow:established,to_server; content:"/exe.php?exp="; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011813; rev:6; metadata:created_at 2010_10_12, updated_at 2010_10_12;)

# 2011813
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS SEO Exploit Kit - client exploited"; flow:established,to_server; content:"/exe.php?exp="; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011813; rev:6; metadata:created_at 2010_10_12, updated_at 2010_10_12;)
` 

Name : **SEO Exploit Kit - client exploited** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-10-12

Last modified date : 2010-10-12

Rev version : 6

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Kit reporting Java and PDF state"; flow:established,to_server; content:"_js?java="; http_uri; fast_pattern; content:"&adobe_pdf="; http_uri; distance:0; pcre:"/\/[a-f0-9]{60,}_js\?/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013690; rev:3; metadata:created_at 2011_09_23, updated_at 2011_09_23;)

# 2013690
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Kit reporting Java and PDF state"; flow:established,to_server; content:"_js?java="; http_uri; fast_pattern; content:"&adobe_pdf="; http_uri; distance:0; pcre:"/\/[a-f0-9]{60,}_js\?/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013690; rev:3; metadata:created_at 2011_09_23, updated_at 2011_09_23;)
` 

Name : **Unknown Exploit Kit reporting Java and PDF state** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-23

Last modified date : 2011-09-23

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Kit Java requesting malicious JAR"; flow:established,to_server; content:"_jar"; http_uri; fast_pattern; content:"|20|Java/"; http_header; pcre:"/\/[a-f0-9]{60,}_jar$/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013691; rev:3; metadata:created_at 2011_09_23, updated_at 2011_09_23;)

# 2013691
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Kit Java requesting malicious JAR"; flow:established,to_server; content:"_jar"; http_uri; fast_pattern; content:"|20|Java/"; http_header; pcre:"/\/[a-f0-9]{60,}_jar$/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013691; rev:3; metadata:created_at 2011_09_23, updated_at 2011_09_23;)
` 

Name : **Unknown Exploit Kit Java requesting malicious JAR** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-23

Last modified date : 2011-09-23

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Kit Java requesting malicious EXE"; flow:established,to_server; content:"_exe"; http_uri; fast_pattern; content:"|20|Java/"; http_header; pcre:"/\/[a-f0-9]{60,}_exe$/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013692; rev:3; metadata:created_at 2011_09_23, updated_at 2011_09_23;)

# 2013692
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Kit Java requesting malicious EXE"; flow:established,to_server; content:"_exe"; http_uri; fast_pattern; content:"|20|Java/"; http_header; pcre:"/\/[a-f0-9]{60,}_exe$/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013692; rev:3; metadata:created_at 2011_09_23, updated_at 2011_09_23;)
` 

Name : **Unknown Exploit Kit Java requesting malicious EXE** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-23

Last modified date : 2011-09-23

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Kit request for pdf_err__Error__Unspecified"; flow:established,to_server; content:"/pdf_err__Error__Unspecified error..gif"; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013693; rev:7; metadata:created_at 2011_09_23, updated_at 2011_09_23;)

# 2013693
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Kit request for pdf_err__Error__Unspecified"; flow:established,to_server; content:"/pdf_err__Error__Unspecified error..gif"; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013693; rev:7; metadata:created_at 2011_09_23, updated_at 2011_09_23;)
` 

Name : **Unknown Exploit Kit request for pdf_err__Error__Unspecified** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-23

Last modified date : 2011-09-23

Rev version : 7

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Phoenix-style Exploit Kit Java Request with semicolon in URI"; flow:established,to_server; content:"/?"; http_uri; content:"|3b| 1|3b| "; http_uri; content:"|29| Java/1."; http_header; pcre:"/\/\?[a-z0-9]{65,}\x3b \d\x3b \d/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2011988; rev:5; metadata:created_at 2010_12_01, updated_at 2017_04_13;)

# 2011988
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Phoenix-style Exploit Kit Java Request with semicolon in URI"; flow:established,to_server; content:"/?"; http_uri; content:"|3b| 1|3b| "; http_uri; content:"|29| Java/1."; http_header; pcre:"/\/\?[a-z0-9]{65,}\x3b \d\x3b \d/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2011988; rev:5; metadata:created_at 2010_12_01, updated_at 2017_04_13;)
` 

Name : **Phoenix-style Exploit Kit Java Request with semicolon in URI** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-12-01

Last modified date : 2017-04-13

Rev version : 5

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Document.write Long Backslash UTF-16 Encoded Content - Exploit Kit Behavior Flowbit Set"; flow:established,to_client; content:"document.write|28 22 5C|u"; nocase; isdataat:100,relative; content:!"|29|"; within:100; content:"|5C|u"; nocase; distance:4; within:2; content:"|5C|u"; nocase; distance:4; within:2; content:"|5C|u"; nocase; distance:4; within:2; content:"|5C|u"; nocase; distance:70; content:"|5C|u"; nocase; distance:4; within:2; flowbits:set,et.exploitkitlanding; flowbits:noalert; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2011/elaborate-black-hole-infection/; classtype:bad-unknown; sid:2014096; rev:6; metadata:created_at 2012_01_04, updated_at 2012_01_04;)

# 2014096
`alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Document.write Long Backslash UTF-16 Encoded Content - Exploit Kit Behavior Flowbit Set"; flow:established,to_client; content:"document.write|28 22 5C|u"; nocase; isdataat:100,relative; content:!"|29|"; within:100; content:"|5C|u"; nocase; distance:4; within:2; content:"|5C|u"; nocase; distance:4; within:2; content:"|5C|u"; nocase; distance:4; within:2; content:"|5C|u"; nocase; distance:70; content:"|5C|u"; nocase; distance:4; within:2; flowbits:set,et.exploitkitlanding; flowbits:noalert; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2011/elaborate-black-hole-infection/; classtype:bad-unknown; sid:2014096; rev:6; metadata:created_at 2012_01_04, updated_at 2012_01_04;)
` 

Name : **Document.write Long Backslash UTF-16 Encoded Content - Exploit Kit Behavior Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.kahusecurity.com/2011/elaborate-black-hole-infection/

CVE reference : Not defined

Creation date : 2012-01-04

Last modified date : 2012-01-04

Rev version : 6

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Excessive new Array With Newline - Exploit Kit Behavior Flowbit Set"; flow:established,to_client; content:" = new Array|28 29 3B|"; nocase; content:" = new Array|28 29 3B|"; nocase; within:100; content:" = new Array|28 29 3B|"; nocase; content:" = new Array|28 29 3B|"; nocase; within:100; content:" = new Array|28 29 3B|"; nocase; content:" = new Array|28 29 3B|"; nocase; within:100; flowbits:set,et.exploitkitlanding; flowbits:noalert; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2011/elaborate-black-hole-infection/; classtype:bad-unknown; sid:2014097; rev:3; metadata:created_at 2012_01_04, updated_at 2012_01_04;)

# 2014097
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Excessive new Array With Newline - Exploit Kit Behavior Flowbit Set"; flow:established,to_client; content:" = new Array|28 29 3B|"; nocase; content:" = new Array|28 29 3B|"; nocase; within:100; content:" = new Array|28 29 3B|"; nocase; content:" = new Array|28 29 3B|"; nocase; within:100; content:" = new Array|28 29 3B|"; nocase; content:" = new Array|28 29 3B|"; nocase; within:100; flowbits:set,et.exploitkitlanding; flowbits:noalert; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2011/elaborate-black-hole-infection/; classtype:bad-unknown; sid:2014097; rev:3; metadata:created_at 2012_01_04, updated_at 2012_01_04;)
` 

Name : **Excessive new Array With Newline - Exploit Kit Behavior Flowbit Set** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.kahusecurity.com/2011/elaborate-black-hole-infection/

CVE reference : Not defined

Creation date : 2012-01-04

Last modified date : 2012-01-04

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY SEO Exploit Kit request for Java exploit"; flow:established,to_server; content:"POST"; http_method; content:"id="; http_client_body; content:"|25 32 36|j"; distance:32; within:4; http_client_body; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011349; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2010_09_28, updated_at 2016_07_01;)

# 2011349
`#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY SEO Exploit Kit request for Java exploit"; flow:established,to_server; content:"POST"; http_method; content:"id="; http_client_body; content:"|25 32 36|j"; distance:32; within:4; http_client_body; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011349; rev:6; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2010_09_28, updated_at 2016_07_01;)
` 

Name : **DRIVEBY SEO Exploit Kit request for Java exploit** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2016-07-01

Rev version : 6

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Kit Landing Response Malicious JavaScript"; flow:established,from_server; content:"<html><body><script>|0d 0a|"; fast_pattern; nocase; content:"document.createElement"; within:50; content:"|28|String["; distance:0; pcre:"/,[0-9\.]+\*\d,[a-z]\+\d+,[0-9\.]+\*\d,[a-z]\+\d+,[0-9\.]+\*\d,[a-z]\+\d+,/iR"; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2013660; rev:4; metadata:created_at 2011_09_15, updated_at 2011_09_15;)

# 2013660
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Unknown Exploit Kit Landing Response Malicious JavaScript"; flow:established,from_server; content:"<html><body><script>|0d 0a|"; fast_pattern; nocase; content:"document.createElement"; within:50; content:"|28|String["; distance:0; pcre:"/,[0-9\.]+\*\d,[a-z]\+\d+,[0-9\.]+\*\d,[a-z]\+\d+,[0-9\.]+\*\d,[a-z]\+\d+,/iR"; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2013660; rev:4; metadata:created_at 2011_09_15, updated_at 2011_09_15;)
` 

Name : **Unknown Exploit Kit Landing Response Malicious JavaScript** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-09-15

Last modified date : 2011-09-15

Rev version : 4

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Jupiter Exploit Kit Landing Page with Malicious Java Applets"; flow:established,from_server; content:"<applet"; content:"code="; content:".jar"; distance:0; content:"u//FCyy"; within:50; fast_pattern; content:"</applet>"; within:100; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2013955; rev:3; metadata:created_at 2011_11_23, updated_at 2011_11_23;)

# 2013955
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Jupiter Exploit Kit Landing Page with Malicious Java Applets"; flow:established,from_server; content:"<applet"; content:"code="; content:".jar"; distance:0; content:"u//FCyy"; within:50; fast_pattern; content:"</applet>"; within:100; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2013955; rev:3; metadata:created_at 2011_11_23, updated_at 2011_11_23;)
` 

Name : **Jupiter Exploit Kit Landing Page with Malicious Java Applets** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-23

Last modified date : 2011-11-23

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Phoenix Exploit Kit Newplayer.pdf"; flow:established,to_server; content:"/newplayer.pdf"; http_uri; metadata: former_category EXPLOIT_KIT; reference:cve,2009-4324; reference:url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp; classtype:attempted-user; sid:2012941; rev:7; metadata:created_at 2011_06_07, updated_at 2017_04_10;)

# 2012941
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Phoenix Exploit Kit Newplayer.pdf"; flow:established,to_server; content:"/newplayer.pdf"; http_uri; metadata: former_category EXPLOIT_KIT; reference:cve,2009-4324; reference:url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp; classtype:attempted-user; sid:2012941; rev:7; metadata:created_at 2011_06_07, updated_at 2017_04_10;)
` 

Name : **Phoenix Exploit Kit Newplayer.pdf** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : cve,2009-4324|url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp

CVE reference : Not defined

Creation date : 2011-06-07

Last modified date : 2017-04-10

Rev version : 7

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Phoenix Exploit Kit Printf.pdf"; flow:established,to_server; content:"/printf.pdf"; http_uri; metadata: former_category EXPLOIT_KIT; reference:cve,2008-2992; reference:url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp; classtype:attempted-user; sid:2012942; rev:7; metadata:created_at 2011_06_07, updated_at 2011_06_07;)

# 2012942
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Phoenix Exploit Kit Printf.pdf"; flow:established,to_server; content:"/printf.pdf"; http_uri; metadata: former_category EXPLOIT_KIT; reference:cve,2008-2992; reference:url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp; classtype:attempted-user; sid:2012942; rev:7; metadata:created_at 2011_06_07, updated_at 2011_06_07;)
` 

Name : **Phoenix Exploit Kit Printf.pdf** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : cve,2008-2992|url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp

CVE reference : Not defined

Creation date : 2011-06-07

Last modified date : 2011-06-07

Rev version : 7

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Phoenix Exploit Kit Geticon.pdf"; flow:established,to_server; content:"/geticon.pdf"; http_uri; metadata: former_category EXPLOIT_KIT; reference:url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp; classtype:attempted-user; sid:2012943; rev:7; metadata:created_at 2011_06_07, updated_at 2011_06_07;)

# 2012943
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Phoenix Exploit Kit Geticon.pdf"; flow:established,to_server; content:"/geticon.pdf"; http_uri; metadata: former_category EXPLOIT_KIT; reference:url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp; classtype:attempted-user; sid:2012943; rev:7; metadata:created_at 2011_06_07, updated_at 2011_06_07;)
` 

Name : **Phoenix Exploit Kit Geticon.pdf** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp

CVE reference : Not defined

Creation date : 2011-06-07

Last modified date : 2011-06-07

Rev version : 7

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Phoenix Exploit Kit All.pdf"; flow:established,to_server; content:"/tmp/all.pdf"; http_uri; metadata: former_category EXPLOIT_KIT; reference:url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp; classtype:attempted-user; sid:2012944; rev:7; metadata:created_at 2011_06_07, updated_at 2011_06_07;)

# 2012944
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Phoenix Exploit Kit All.pdf"; flow:established,to_server; content:"/tmp/all.pdf"; http_uri; metadata: former_category EXPLOIT_KIT; reference:url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp; classtype:attempted-user; sid:2012944; rev:7; metadata:created_at 2011_06_07, updated_at 2011_06_07;)
` 

Name : **Phoenix Exploit Kit All.pdf** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.m86security.com/labs/i/Phoenix-Exploit-Kit-2-0,trace.1427~.asp

CVE reference : Not defined

Creation date : 2011-06-07

Last modified date : 2011-06-07

Rev version : 7

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Saturn Exploit Kit probable Java exploit request"; flow:established,to_server; content:"/dl/apache.php"; depth:14; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013776; rev:3; metadata:created_at 2011_10_13, updated_at 2011_10_13;)

# 2013776
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Saturn Exploit Kit probable Java exploit request"; flow:established,to_server; content:"/dl/apache.php"; depth:14; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013776; rev:3; metadata:created_at 2011_10_13, updated_at 2011_10_13;)
` 

Name : **Saturn Exploit Kit probable Java exploit request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-10-13

Last modified date : 2011-10-13

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS PDF served from /tmp/ could be Phoenix Exploit Kit"; flow:established,to_server; content:"/tmp/"; http_uri; content:".pdf"; http_uri; pcre:"/\/tmp\/[^\/]+\.pdf$/U"; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2011972; rev:3; metadata:created_at 2010_11_23, updated_at 2010_11_23;)

# 2011972
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS PDF served from /tmp/ could be Phoenix Exploit Kit"; flow:established,to_server; content:"/tmp/"; http_uri; content:".pdf"; http_uri; pcre:"/\/tmp\/[^\/]+\.pdf$/U"; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2011972; rev:3; metadata:created_at 2010_11_23, updated_at 2010_11_23;)
` 

Name : **PDF served from /tmp/ could be Phoenix Exploit Kit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-11-23

Last modified date : 2010-11-23

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS JAR served from /tmp/ could be Phoenix Exploit Kit"; flow:established,to_server; content:"/tmp/"; http_uri; fast_pattern; content:".jar"; http_uri; pcre:"/\/tmp\/[^\/]+\.jar$/U"; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2011973; rev:3; metadata:created_at 2010_11_23, updated_at 2010_11_23;)

# 2011973
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS JAR served from /tmp/ could be Phoenix Exploit Kit"; flow:established,to_server; content:"/tmp/"; http_uri; fast_pattern; content:".jar"; http_uri; pcre:"/\/tmp\/[^\/]+\.jar$/U"; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2011973; rev:3; metadata:created_at 2010_11_23, updated_at 2010_11_23;)
` 

Name : **JAR served from /tmp/ could be Phoenix Exploit Kit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-11-23

Last modified date : 2010-11-23

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY SEO Exploit Kit request for Java and PDF exploits"; flow:established,to_server; content:"POST"; http_method; content:"id="; http_client_body; content:"|25 32 36|jp"; distance:5; within:5; http_client_body; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011350; rev:8; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2010_09_28, updated_at 2016_07_01;)

# 2011350
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY SEO Exploit Kit request for Java and PDF exploits"; flow:established,to_server; content:"POST"; http_method; content:"id="; http_client_body; content:"|25 32 36|jp"; distance:5; within:5; http_client_body; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011350; rev:8; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2010_09_28, updated_at 2016_07_01;)
` 

Name : **DRIVEBY SEO Exploit Kit request for Java and PDF exploits** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-28

Last modified date : 2016-07-01

Rev version : 8

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Adobe Flash SWF File Embedded in XLS FILE Caution - Could be Exploit"; flow:established,from_server; content:"|0D 0A 0D 0A D0 CF 11 E0 A1 B1 1A E1|"; content:"SWF"; fast_pattern:only; reference:url,blogs.adobe.com/asset/2011/03/background-on-apsa11-01-patch-schedule.html; reference:url,bugix-security.blogspot.com/2011/03/cve-2011-0609-adobe-flash-player.html; reference:bid,46860; reference:cve,2011-0609; classtype:attempted-user; sid:2012621; rev:4; metadata:created_at 2011_03_31, updated_at 2011_03_31;)

# 2012621
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Adobe Flash SWF File Embedded in XLS FILE Caution - Could be Exploit"; flow:established,from_server; content:"|0D 0A 0D 0A D0 CF 11 E0 A1 B1 1A E1|"; content:"SWF"; fast_pattern:only; reference:url,blogs.adobe.com/asset/2011/03/background-on-apsa11-01-patch-schedule.html; reference:url,bugix-security.blogspot.com/2011/03/cve-2011-0609-adobe-flash-player.html; reference:bid,46860; reference:cve,2011-0609; classtype:attempted-user; sid:2012621; rev:4; metadata:created_at 2011_03_31, updated_at 2011_03_31;)
` 

Name : **Adobe Flash SWF File Embedded in XLS FILE Caution - Could be Exploit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,blogs.adobe.com/asset/2011/03/background-on-apsa11-01-patch-schedule.html|url,bugix-security.blogspot.com/2011/03/cve-2011-0609-adobe-flash-player.html|bid,46860|cve,2011-0609

CVE reference : Not defined

Creation date : 2011-03-31

Last modified date : 2011-03-31

Rev version : 4

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Sakura Exploit Kit Landing Page Request"; flow:established,to_server; content:".php?s="; http_uri; pcre:"/\.php\?s=[0-9a-fA-F]{25}$/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; reference:url,xylibox.blogspot.com/2012/01/sakura-exploit-pack-10.html; classtype:bad-unknown; sid:2014147; rev:2; metadata:created_at 2012_01_23, updated_at 2012_01_23;)

# 2014147
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Sakura Exploit Kit Landing Page Request"; flow:established,to_server; content:".php?s="; http_uri; pcre:"/\.php\?s=[0-9a-fA-F]{25}$/U"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; reference:url,xylibox.blogspot.com/2012/01/sakura-exploit-pack-10.html; classtype:bad-unknown; sid:2014147; rev:2; metadata:created_at 2012_01_23, updated_at 2012_01_23;)
` 

Name : **Sakura Exploit Kit Landing Page Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,xylibox.blogspot.com/2012/01/sakura-exploit-pack-10.html

CVE reference : Not defined

Creation date : 2012-01-23

Last modified date : 2012-01-23

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Sakura Exploit Kit Binary Load Request"; flow:established,to_server; content:"/load.php?spl="; http_uri; pcre:"/\/load\.php\?spl=[-_\w]+$/U"; metadata: former_category EXPLOIT_KIT; classtype:attempted-user; sid:2014148; rev:2; metadata:created_at 2012_01_23, updated_at 2012_01_23;)

# 2014148
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Sakura Exploit Kit Binary Load Request"; flow:established,to_server; content:"/load.php?spl="; http_uri; pcre:"/\/load\.php\?spl=[-_\w]+$/U"; metadata: former_category EXPLOIT_KIT; classtype:attempted-user; sid:2014148; rev:2; metadata:created_at 2012_01_23, updated_at 2012_01_23;)
` 

Name : **Sakura Exploit Kit Binary Load Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-01-23

Last modified date : 2012-01-23

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Clickfraud Framework Request"; flow:to_server,established; content:"/go.php?uid="; http_uri; fast_pattern; content:"&data="; http_uri; urilen:>400; classtype:bad-unknown; sid:2013093; rev:3; metadata:created_at 2011_06_22, updated_at 2011_06_22;)

# 2013093
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Clickfraud Framework Request"; flow:to_server,established; content:"/go.php?uid="; http_uri; fast_pattern; content:"&data="; http_uri; urilen:>400; classtype:bad-unknown; sid:2013093; rev:3; metadata:created_at 2011_06_22, updated_at 2011_06_22;)
` 

Name : **Clickfraud Framework Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-06-22

Last modified date : 2011-06-22

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Known Malicious Link Leading to Exploit Kits (t.php?id=is1)"; flow:established,to_server; content:"/t.php?id=is1"; http_uri; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2014151; rev:2; metadata:created_at 2012_01_26, updated_at 2012_01_26;)

# 2014151
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Known Malicious Link Leading to Exploit Kits (t.php?id=is1)"; flow:established,to_server; content:"/t.php?id=is1"; http_uri; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2014151; rev:2; metadata:created_at 2012_01_26, updated_at 2012_01_26;)
` 

Name : **Known Malicious Link Leading to Exploit Kits (t.php?id=is1)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-01-26

Last modified date : 2012-01-26

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Incognito Exploit Kit Java request to showthread.php?t="; flow:established,to_server; content:"/showthread.php?t="; http_uri; content:"|29 20|Java/"; http_header; pcre:"/^\/showthread\.php\?t=\d+$/Ui"; metadata: former_category EXPLOIT_KIT; reference:url,research.zscaler.com/2012/01/popularity-of-exploit-kits-leading-to.html; classtype:trojan-activity; sid:2013916; rev:6; metadata:created_at 2011_11_16, updated_at 2011_11_16;)

# 2013916
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Incognito Exploit Kit Java request to showthread.php?t="; flow:established,to_server; content:"/showthread.php?t="; http_uri; content:"|29 20|Java/"; http_header; pcre:"/^\/showthread\.php\?t=\d+$/Ui"; metadata: former_category EXPLOIT_KIT; reference:url,research.zscaler.com/2012/01/popularity-of-exploit-kits-leading-to.html; classtype:trojan-activity; sid:2013916; rev:6; metadata:created_at 2011_11_16, updated_at 2011_11_16;)
` 

Name : **Incognito Exploit Kit Java request to showthread.php?t=** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,research.zscaler.com/2012/01/popularity-of-exploit-kits-leading-to.html

CVE reference : Not defined

Creation date : 2011-11-16

Last modified date : 2011-11-16

Rev version : 6

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Yang Pack Exploit Kit Landing Page Known JavaScript Function Detected"; flow:established,to_client; content:"function booom"; nocase; pcre:"/function\x20booom[1-3]{1}\x28\x29/smi"; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2012/chinese-exploit-packs/; classtype:trojan-activity; sid:2014197; rev:2; metadata:created_at 2012_02_06, updated_at 2012_02_06;)

# 2014197
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Yang Pack Exploit Kit Landing Page Known JavaScript Function Detected"; flow:established,to_client; content:"function booom"; nocase; pcre:"/function\x20booom[1-3]{1}\x28\x29/smi"; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2012/chinese-exploit-packs/; classtype:trojan-activity; sid:2014197; rev:2; metadata:created_at 2012_02_06, updated_at 2012_02_06;)
` 

Name : **Yang Pack Exploit Kit Landing Page Known JavaScript Function Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.kahusecurity.com/2012/chinese-exploit-packs/

CVE reference : Not defined

Creation date : 2012-02-06

Last modified date : 2012-02-06

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Exploit Kit Exploiting IEPeers"; flow:established,to_client; content:"booom["; content:"booom["; distance:0; content:"booom["; distance:0; content:"booom["; distance:0; content:"booom["; distance:0; content:"booom["; distance:0; content:"booom["; distance:0; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2011/cve-2011-2140-caught-in-the-wild/; reference:cve,2010-0806; classtype:trojan-activity; sid:2014199; rev:1; metadata:created_at 2012_02_07, updated_at 2016_11_01;)

# 2014199
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Exploit Kit Exploiting IEPeers"; flow:established,to_client; content:"booom["; content:"booom["; distance:0; content:"booom["; distance:0; content:"booom["; distance:0; content:"booom["; distance:0; content:"booom["; distance:0; content:"booom["; distance:0; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2011/cve-2011-2140-caught-in-the-wild/; reference:cve,2010-0806; classtype:trojan-activity; sid:2014199; rev:1; metadata:created_at 2012_02_07, updated_at 2016_11_01;)
` 

Name : **Exploit Kit Exploiting IEPeers** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.kahusecurity.com/2011/cve-2011-2140-caught-in-the-wild/|cve,2010-0806

CVE reference : Not defined

Creation date : 2012-02-07

Last modified date : 2016-11-01

Rev version : 1

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS CUTE-IE.html CutePack Exploit Kit Landing Page Request"; flow:established,to_server; content:"/CUTE-IE.html"; nocase; http_uri; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2012/chinese-exploit-packs/; classtype:trojan-activity; sid:2014203; rev:3; metadata:created_at 2012_02_07, updated_at 2012_02_07;)

# 2014203
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS CUTE-IE.html CutePack Exploit Kit Landing Page Request"; flow:established,to_server; content:"/CUTE-IE.html"; nocase; http_uri; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2012/chinese-exploit-packs/; classtype:trojan-activity; sid:2014203; rev:3; metadata:created_at 2012_02_07, updated_at 2012_02_07;)
` 

Name : **CUTE-IE.html CutePack Exploit Kit Landing Page Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.kahusecurity.com/2012/chinese-exploit-packs/

CVE reference : Not defined

Creation date : 2012-02-07

Last modified date : 2012-02-07

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS CutePack Exploit Kit JavaScript Variable Detected"; flow:established,to_client; content:"var Cute"; nocase; fast_pattern:only; pcre:"/var\x20Cute(Money|Power|Shine)/smi"; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2012/chinese-exploit-packs/; classtype:trojan-activity; sid:2014204; rev:1; metadata:created_at 2012_02_07, updated_at 2012_02_07;)

# 2014204
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS CutePack Exploit Kit JavaScript Variable Detected"; flow:established,to_client; content:"var Cute"; nocase; fast_pattern:only; pcre:"/var\x20Cute(Money|Power|Shine)/smi"; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2012/chinese-exploit-packs/; classtype:trojan-activity; sid:2014204; rev:1; metadata:created_at 2012_02_07, updated_at 2012_02_07;)
` 

Name : **CutePack Exploit Kit JavaScript Variable Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.kahusecurity.com/2012/chinese-exploit-packs/

CVE reference : Not defined

Creation date : 2012-02-07

Last modified date : 2012-02-07

Rev version : 1

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS CUTE-IE.html CutePack Exploit Kit Iframe for Landing Page Detected"; flow:established,to_client; content:"/CUTE-IE.html"; nocase; fast_pattern:only; pcre:"/iframe[^\r\n]*\x2FCUTE-IE\x2Ehtml/smi"; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2012/chinese-exploit-packs/; classtype:trojan-activity; sid:2014205; rev:1; metadata:created_at 2012_02_07, updated_at 2012_02_07;)

# 2014205
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS CUTE-IE.html CutePack Exploit Kit Iframe for Landing Page Detected"; flow:established,to_client; content:"/CUTE-IE.html"; nocase; fast_pattern:only; pcre:"/iframe[^\r\n]*\x2FCUTE-IE\x2Ehtml/smi"; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2012/chinese-exploit-packs/; classtype:trojan-activity; sid:2014205; rev:1; metadata:created_at 2012_02_07, updated_at 2012_02_07;)
` 

Name : **CUTE-IE.html CutePack Exploit Kit Iframe for Landing Page Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.kahusecurity.com/2012/chinese-exploit-packs/

CVE reference : Not defined

Creation date : 2012-02-07

Last modified date : 2012-02-07

Rev version : 1

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS CutePack Exploit Kit Landing Page Detected"; flow:established,to_client; content:"button id=|22|evilcute|22|"; nocase; fast_pattern:only; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2012/chinese-exploit-packs/; classtype:trojan-activity; sid:2014206; rev:1; metadata:created_at 2012_02_07, updated_at 2012_02_07;)

# 2014206
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS CutePack Exploit Kit Landing Page Detected"; flow:established,to_client; content:"button id=|22|evilcute|22|"; nocase; fast_pattern:only; metadata: former_category EXPLOIT_KIT; reference:url,www.kahusecurity.com/2012/chinese-exploit-packs/; classtype:trojan-activity; sid:2014206; rev:1; metadata:created_at 2012_02_07, updated_at 2012_02_07;)
` 

Name : **CutePack Exploit Kit Landing Page Detected** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,www.kahusecurity.com/2012/chinese-exploit-packs/

CVE reference : Not defined

Creation date : 2012-02-07

Last modified date : 2012-02-07

Rev version : 1

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Obfuscated Content Using Dadongs JSXX 0.41 VIP Obfuscation Script"; flow:established,to_client; content:"document.cookie=|22|dadong"; fast_pattern:17,6; nocase; reference:url,www.kahusecurity.com/2012/chinese-pack-using-dadongs-jsxx-vip-script/; classtype:bad-unknown; sid:2014308; rev:1; metadata:created_at 2012_03_05, updated_at 2012_03_05;)

# 2014308
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Obfuscated Content Using Dadongs JSXX 0.41 VIP Obfuscation Script"; flow:established,to_client; content:"document.cookie=|22|dadong"; fast_pattern:17,6; nocase; reference:url,www.kahusecurity.com/2012/chinese-pack-using-dadongs-jsxx-vip-script/; classtype:bad-unknown; sid:2014308; rev:1; metadata:created_at 2012_03_05, updated_at 2012_03_05;)
` 

Name : **Obfuscated Content Using Dadongs JSXX 0.41 VIP Obfuscation Script** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : url,www.kahusecurity.com/2012/chinese-pack-using-dadongs-jsxx-vip-script/

CVE reference : Not defined

Creation date : 2012-03-05

Last modified date : 2012-03-05

Rev version : 1

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY Incognito libtiff PDF Exploit Requested"; flow:established,to_server; content:"/lib.php"; http_uri; content:".php?showtopic="; http_header; classtype:trojan-activity; sid:2014315; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2012_03_05, updated_at 2016_07_01;)

# 2014315
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS DRIVEBY Incognito libtiff PDF Exploit Requested"; flow:established,to_server; content:"/lib.php"; http_uri; content:".php?showtopic="; http_header; classtype:trojan-activity; sid:2014315; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2012_03_05, updated_at 2016_07_01;)
` 

Name : **DRIVEBY Incognito libtiff PDF Exploit Requested** 

Attack target : Client_Endpoint

Description : Emerging Threats “Driveby” signatures indicate that a malicious event has been observed, typically associated with exploit kits or watering hole attacks. This traffic occurs as legitimate activity on the part of the user, they are browsing a website which happens to either be compromised or loads malicious content which is embedded from a third party such as malvertizing. The user’s web browser and installed plugins  are then subjected to an exploit kit which attempts to compromise their system.

Emerging Threats “Driveby” signatures historically includes activity from many exploit kits, including but not limited to:

Angler
Archie
Blackhole
Crimepack
Flashpack / Critx
Goon/Infinity
Magnitude
NeoSploit
Nuclear
Redkit
SPL
Styx
Sweet Orange

Emerging Threats “Driveby” signatures also includes activity from many exploit kits observed in use by APT groups such as Sednit and Scanbox. Generic signatures are also included in this category of signatures which involved an unsuspecting user being subjected to browser and plugin exploits as a byproduct of normal web browsing activity.

In order to determine if a machine is compromised, or if the signature is an FP/FN, you should look at other signatures that fire against the client endpoint to determine if you see a chain of activity.  Typically if an exploit is successful you will see activity such as redirectors, landing pages, exploits, and ultimately command and control traffic.  Seeing only a driveby signature may indicate that the endpoint was attacked, but it may not be fully compromised.  You can further review the offending web servers in ET Intelligence for further validation to see if they have malicious reputation.

Tags : DriveBy

Affected products : Any

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-03-05

Last modified date : 2016-07-01

Rev version : 2

Category : EXPLOIT_KIT

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Clickpayz redirection to *.clickpayz.com"; flow:established,from_server; content:"HTTP/1.1 30"; depth:11; content:"clickpayz.com/"; classtype:bad-unknown; sid:2014318; rev:2; metadata:created_at 2012_03_05, updated_at 2012_03_05;)

# 2014318
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Clickpayz redirection to *.clickpayz.com"; flow:established,from_server; content:"HTTP/1.1 30"; depth:11; content:"clickpayz.com/"; classtype:bad-unknown; sid:2014318; rev:2; metadata:created_at 2012_03_05, updated_at 2012_03_05;)
` 

Name : **Clickpayz redirection to *.clickpayz.com** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-03-05

Last modified date : 2012-03-05

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Dadong Java Exploit Requested"; flow:established,to_server; content:"/Gondad.jpg"; nocase; http_uri; content:" Java/1"; http_header; classtype:bad-unknown; sid:2014319; rev:2; metadata:created_at 2012_03_05, updated_at 2012_03_05;)

# 2014319
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Dadong Java Exploit Requested"; flow:established,to_server; content:"/Gondad.jpg"; nocase; http_uri; content:" Java/1"; http_header; classtype:bad-unknown; sid:2014319; rev:2; metadata:created_at 2012_03_05, updated_at 2012_03_05;)
` 

Name : **Dadong Java Exploit Requested** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-03-05

Last modified date : 2012-03-05

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Likely Scalaxy Exploit Kit URL template download"; flow:established,from_server; content:"<script>a=|22|http|3a|//"; content:"/tttttt"; fast_pattern; within:50; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2014362; rev:3; metadata:created_at 2012_03_09, updated_at 2012_03_09;)

# 2014362
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Likely Scalaxy Exploit Kit URL template download"; flow:established,from_server; content:"<script>a=|22|http|3a|//"; content:"/tttttt"; fast_pattern; within:50; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2014362; rev:3; metadata:created_at 2012_03_09, updated_at 2012_03_09;)
` 

Name : **Likely Scalaxy Exploit Kit URL template download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-03-09

Last modified date : 2012-03-09

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Probable Scalaxy exploit kit secondary request"; flow:established,to_server; content:"=1.6.0_"; http_uri; pcre:"/^\/[a-z][0-9a-z_+=-]{10,30}\?\w=[0-9.]+\&\w=1.6.0_\d\d$/Ui"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2014024; rev:4; metadata:created_at 2011_12_12, updated_at 2011_12_12;)

# 2014024
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Probable Scalaxy exploit kit secondary request"; flow:established,to_server; content:"=1.6.0_"; http_uri; pcre:"/^\/[a-z][0-9a-z_+=-]{10,30}\?\w=[0-9.]+\&\w=1.6.0_\d\d$/Ui"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2014024; rev:4; metadata:created_at 2011_12_12, updated_at 2011_12_12;)
` 

Name : **Probable Scalaxy exploit kit secondary request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-12-12

Last modified date : 2011-12-12

Rev version : 4

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Java Rhino Exploit Attempt - evilcode.class"; flow:established,to_client; content:"code=|22|evilcode.class|22|"; nocase; fast_pattern:only; reference:cve,2011-3544; classtype:attempted-user; sid:2014429; rev:5; metadata:created_at 2012_03_26, updated_at 2012_03_26;)

# 2014429
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET CURRENT_EVENTS Java Rhino Exploit Attempt - evilcode.class"; flow:established,to_client; content:"code=|22|evilcode.class|22|"; nocase; fast_pattern:only; reference:cve,2011-3544; classtype:attempted-user; sid:2014429; rev:5; metadata:created_at 2012_03_26, updated_at 2012_03_26;)
` 

Name : **Java Rhino Exploit Attempt - evilcode.class** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : cve,2011-3544

CVE reference : Not defined

Creation date : 2012-03-26

Last modified date : 2012-03-26

Rev version : 5

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Possible Dynamic DNS Exploit Pack Landing Page /de/sN"; flow:established,to_server; content:"/de/s"; http_uri; depth:5; urilen:6; flowbits:set,et.exploitkitlanding;  classtype:bad-unknown; sid:2014446; rev:2; metadata:created_at 2012_03_30, updated_at 2012_03_30;)

# 2014446
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Possible Dynamic DNS Exploit Pack Landing Page /de/sN"; flow:established,to_server; content:"/de/s"; http_uri; depth:5; urilen:6; flowbits:set,et.exploitkitlanding;  classtype:bad-unknown; sid:2014446; rev:2; metadata:created_at 2012_03_30, updated_at 2012_03_30;)
` 

Name : **Possible Dynamic DNS Exploit Pack Landing Page /de/sN** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-03-30

Last modified date : 2012-03-30

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Possible Dynamic Dns Exploit Pack Java exploit"; flow:established,to_server; content:"/de/"; http_uri; depth:4; content:".jar"; http_uri; distance:32; within:4; flowbits:set,et.exploitkitlanding; classtype:bad-unknown; sid:2014447; rev:6; metadata:created_at 2012_03_30, updated_at 2012_03_30;)

# 2014447
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Possible Dynamic Dns Exploit Pack Java exploit"; flow:established,to_server; content:"/de/"; http_uri; depth:4; content:".jar"; http_uri; distance:32; within:4; flowbits:set,et.exploitkitlanding; classtype:bad-unknown; sid:2014447; rev:6; metadata:created_at 2012_03_30, updated_at 2012_03_30;)
` 

Name : **Possible Dynamic Dns Exploit Pack Java exploit** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-03-30

Last modified date : 2012-03-30

Rev version : 6

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS SEO Exploit Kit - Landing Page"; flow:established,to_client; content:"<div id=\"obj\"></div><div id=\"pdf\"></div><div id=\"hcp\">"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011812; rev:4; metadata:created_at 2010_10_12, updated_at 2017_04_13;)

# 2011812
`#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS SEO Exploit Kit - Landing Page"; flow:established,to_client; content:"<div id=\"obj\"></div><div id=\"pdf\"></div><div id=\"hcp\">"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:bad-unknown; sid:2011812; rev:4; metadata:created_at 2010_10_12, updated_at 2017_04_13;)
` 

Name : **SEO Exploit Kit - Landing Page** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-10-12

Last modified date : 2017-04-13

Rev version : 4

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Italian Spam Campaign"; flow:established,to_server; content:"/Dettagli.zip"; http_uri; reference:md5,c64504b68d34b18a370f5e77bd0b0337; classtype:trojan-activity; sid:2014458; rev:3; metadata:created_at 2012_04_03, updated_at 2012_04_03;)

# 2014458
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Italian Spam Campaign"; flow:established,to_server; content:"/Dettagli.zip"; http_uri; reference:md5,c64504b68d34b18a370f5e77bd0b0337; classtype:trojan-activity; sid:2014458; rev:3; metadata:created_at 2012_04_03, updated_at 2012_04_03;)
` 

Name : **Italian Spam Campaign** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : md5,c64504b68d34b18a370f5e77bd0b0337

CVE reference : Not defined

Creation date : 2012-04-03

Last modified date : 2012-04-03

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Malicious TDS /indigo?"; flow:to_server,established; content:"/indigo?"; http_uri; pcre:"/\/indigo\?\d+/U"; classtype:bad-unknown; sid:2014539; rev:2; metadata:created_at 2012_04_11, updated_at 2012_04_11;)

# 2014539
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Malicious TDS /indigo?"; flow:to_server,established; content:"/indigo?"; http_uri; pcre:"/\/indigo\?\d+/U"; classtype:bad-unknown; sid:2014539; rev:2; metadata:created_at 2012_04_11, updated_at 2012_04_11;)
` 

Name : **Malicious TDS /indigo?** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-11

Last modified date : 2012-04-11

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS TDS Sutra - request in.cgi"; flow:to_server,established; content:"/in.cgi"; http_uri; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2014543; rev:2; metadata:created_at 2012_04_12, updated_at 2017_11_28;)

# 2014543
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS TDS Sutra - request in.cgi"; flow:to_server,established; content:"/in.cgi"; http_uri; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2014543; rev:2; metadata:created_at 2012_04_12, updated_at 2017_11_28;)
` 

Name : **TDS Sutra - request in.cgi** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-12

Last modified date : 2017-11-28

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS TDS Sutra - HTTP header redirecting to a SutraTDS"; flow:established,to_client; content:"/in.cgi"; http_header; classtype:bad-unknown; sid:2014546; rev:5; metadata:created_at 2012_04_12, updated_at 2012_04_12;)

# 2014546
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS TDS Sutra - HTTP header redirecting to a SutraTDS"; flow:established,to_client; content:"/in.cgi"; http_header; classtype:bad-unknown; sid:2014546; rev:5; metadata:created_at 2012_04_12, updated_at 2012_04_12;)
` 

Name : **TDS Sutra - HTTP header redirecting to a SutraTDS** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-12

Last modified date : 2012-04-12

Rev version : 5

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unkown exploit kit version check"; flow:established,to_server; content:"GET"; http_method; content:".php?"; http_uri; content:"x="; http_uri; content:"&u="; http_uri; content:"&s="; http_uri; content:"&t="; http_uri; content:"&java"; http_uri; fast_pattern; content:"&pdf="; http_uri; content:"&flash="; content:"&qt="; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014569; rev:5; metadata:created_at 2012_04_16, updated_at 2012_04_16;)

# 2014569
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unkown exploit kit version check"; flow:established,to_server; content:"GET"; http_method; content:".php?"; http_uri; content:"x="; http_uri; content:"&u="; http_uri; content:"&s="; http_uri; content:"&t="; http_uri; content:"&java"; http_uri; fast_pattern; content:"&pdf="; http_uri; content:"&flash="; content:"&qt="; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014569; rev:5; metadata:created_at 2012_04_16, updated_at 2012_04_16;)
` 

Name : **Unkown exploit kit version check** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-16

Last modified date : 2012-04-16

Rev version : 5

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Incognito Exploit Kit Java request to images.php?t="; flow:established,to_server; content:"/images.php?t="; http_uri; content:"|29 20|Java/"; http_header; pcre:"/^\/images\.php\?t=\d+$/Ui"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014609; rev:2; metadata:created_at 2012_04_17, updated_at 2012_04_17;)

# 2014609
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Incognito Exploit Kit Java request to images.php?t="; flow:established,to_server; content:"/images.php?t="; http_uri; content:"|29 20|Java/"; http_header; pcre:"/^\/images\.php\?t=\d+$/Ui"; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014609; rev:2; metadata:created_at 2012_04_17, updated_at 2012_04_17;)
` 

Name : **Incognito Exploit Kit Java request to images.php?t=** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-17

Last modified date : 2012-04-17

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Jembot PHP Webshell (hell.php)"; flow:established,to_server; content:"/hell.php"; http_uri; nocase; reference:url,lab.onsec.ru/2012/04/find-new-web-bot-jembot.html?m=1; classtype:web-application-activity; sid:2014615; rev:3; metadata:created_at 2012_04_17, updated_at 2012_04_17;)

# 2014615
`#alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Jembot PHP Webshell (hell.php)"; flow:established,to_server; content:"/hell.php"; http_uri; nocase; reference:url,lab.onsec.ru/2012/04/find-new-web-bot-jembot.html?m=1; classtype:web-application-activity; sid:2014615; rev:3; metadata:created_at 2012_04_17, updated_at 2012_04_17;)
` 

Name : **Jembot PHP Webshell (hell.php)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-activity

URL reference : url,lab.onsec.ru/2012/04/find-new-web-bot-jembot.html?m=1

CVE reference : Not defined

Creation date : 2012-04-17

Last modified date : 2012-04-17

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET CURRENT_EVENTS Suspicious Self Signed SSL Certificate CN of common Possible SSL CnC"; flow:established,from_server; content:"|16 03|"; content:"|0b|"; within:7; content:"common1|1b|0"; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2013805; rev:4; metadata:attack_target Client_Endpoint, deployment Perimeter, tag SSL_Malicious_Cert, signature_severity Major, created_at 2011_10_25, updated_at 2016_07_01;)

# 2013805
`#alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET CURRENT_EVENTS Suspicious Self Signed SSL Certificate CN of common Possible SSL CnC"; flow:established,from_server; content:"|16 03|"; content:"|0b|"; within:7; content:"common1|1b|0"; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2013805; rev:4; metadata:attack_target Client_Endpoint, deployment Perimeter, tag SSL_Malicious_Cert, signature_severity Major, created_at 2011_10_25, updated_at 2016_07_01;)
` 

Name : **Suspicious Self Signed SSL Certificate CN of common Possible SSL CnC** 

Attack target : Client_Endpoint

Description : SSL signatures are commonly used to detect the traffic of a known malicious binary. When a SSL or TLS certificate is used to encrypt traffic, the contents of the traffic are generally not observable without prior MiTM or decryption with a valid certificate. SSL / TLS usage is extremely common on the modern internet and the generation of certificates are readily available to malware authors who are looking for a way to protect the contents of their traffic from inspection by analysts.

Popular malware families who have historically made use of SSL certificates include but are not limited to:

Dridex
Dyre
Geodo
Gootkit
Gozi
Kins
Quakbot
Tinba
TorrentLocker
Upatre
Ursnif
Vawtrak
Zbot/Zeus Variants

Emerging Threats also provides coverage for SSL Certificates that possess unique characteristics that would indicate probable maliciousness. These can include purposes such as malvertising, redirectors, and injects. Malvertising and redirector signatures include certificates that have been observed to lead visitors to malicious content such as exploit kits. Inject signatures include certificates that have been observed in use by malware that injects itself into running processes and steals information such as user credentials.

SSL Cert signatures are primarily targeting the specific known static SSL certificates used by malware or specific fields within the SSL server certificates used by known malware.  This means that the likelihood of false positives with these signatures are typically very low and seeing an SSL Cert for known malware exchanged is a high fidelity indicator that the asset is compromised.  You can further validate whether an asset is compromised by looking for other IOC’s such as the client talking to a known Command and Control system in ET Intelligence, as well as other related malware signatures triggering on the endpoint.

Tags : SSL_Malicious_Cert

Affected products : Not defined

Alert Classtype : command-and-control

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-10-25

Last modified date : 2016-07-01

Rev version : 4

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET CURRENT_EVENTS Suspicious Self Signed SSL Certificate with admin@common Possible SSL CnC"; flow:established,from_server; content:"|16 03|"; content:"|0b|"; within:7; content:"admin@common"; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2013806; rev:4; metadata:attack_target Client_Endpoint, deployment Perimeter, tag SSL_Malicious_Cert, signature_severity Major, created_at 2011_10_25, updated_at 2016_07_01;)

# 2013806
`#alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET CURRENT_EVENTS Suspicious Self Signed SSL Certificate with admin@common Possible SSL CnC"; flow:established,from_server; content:"|16 03|"; content:"|0b|"; within:7; content:"admin@common"; metadata: former_category CURRENT_EVENTS; classtype:bad-unknown; sid:2013806; rev:4; metadata:attack_target Client_Endpoint, deployment Perimeter, tag SSL_Malicious_Cert, signature_severity Major, created_at 2011_10_25, updated_at 2016_07_01;)
` 

Name : **Suspicious Self Signed SSL Certificate with admin@common Possible SSL CnC** 

Attack target : Client_Endpoint

Description : SSL signatures are commonly used to detect the traffic of a known malicious binary. When a SSL or TLS certificate is used to encrypt traffic, the contents of the traffic are generally not observable without prior MiTM or decryption with a valid certificate. SSL / TLS usage is extremely common on the modern internet and the generation of certificates are readily available to malware authors who are looking for a way to protect the contents of their traffic from inspection by analysts.

Popular malware families who have historically made use of SSL certificates include but are not limited to:

Dridex
Dyre
Geodo
Gootkit
Gozi
Kins
Quakbot
Tinba
TorrentLocker
Upatre
Ursnif
Vawtrak
Zbot/Zeus Variants

Emerging Threats also provides coverage for SSL Certificates that possess unique characteristics that would indicate probable maliciousness. These can include purposes such as malvertising, redirectors, and injects. Malvertising and redirector signatures include certificates that have been observed to lead visitors to malicious content such as exploit kits. Inject signatures include certificates that have been observed in use by malware that injects itself into running processes and steals information such as user credentials.

SSL Cert signatures are primarily targeting the specific known static SSL certificates used by malware or specific fields within the SSL server certificates used by known malware.  This means that the likelihood of false positives with these signatures are typically very low and seeing an SSL Cert for known malware exchanged is a high fidelity indicator that the asset is compromised.  You can further validate whether an asset is compromised by looking for other IOC’s such as the client talking to a known Command and Control system in ET Intelligence, as well as other related malware signatures triggering on the endpoint.

Tags : SSL_Malicious_Cert

Affected products : Not defined

Alert Classtype : command-and-control

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-10-25

Last modified date : 2016-07-01

Rev version : 4

Category : HUNTING

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Incognito Exploit Kit payload request to images.php?t=N"; flow:established,to_server; content:"/images.php?t="; http_uri; urilen:15; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014640; rev:1; metadata:created_at 2012_04_26, updated_at 2012_04_26;)

# 2014640
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Incognito Exploit Kit payload request to images.php?t=N"; flow:established,to_server; content:"/images.php?t="; http_uri; urilen:15; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014640; rev:1; metadata:created_at 2012_04_26, updated_at 2012_04_26;)
` 

Name : **Incognito Exploit Kit payload request to images.php?t=N** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-26

Last modified date : 2012-04-26

Rev version : 1

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Incognito Exploit Kit PDF request to images.php?t=81118"; flow:established,to_server; content:"/images.php?t=81118"; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014639; rev:2; metadata:created_at 2012_04_26, updated_at 2012_04_26;)

# 2014639
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Incognito Exploit Kit PDF request to images.php?t=81118"; flow:established,to_server; content:"/images.php?t=81118"; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014639; rev:2; metadata:created_at 2012_04_26, updated_at 2012_04_26;)
` 

Name : **Incognito Exploit Kit PDF request to images.php?t=81118** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-26

Last modified date : 2012-04-26

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Neosploit Java Exploit Kit request to /? plus hex 32"; flow:established,to_server; content:"/?"; http_uri; fast_pattern; content:" Java/"; http_header; pcre:"/^\/\?[a-f0-9]{32}$/U"; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013975; rev:3; metadata:created_at 2011_11_30, updated_at 2011_11_30;)

# 2013975
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Neosploit Java Exploit Kit request to /? plus hex 32"; flow:established,to_server; content:"/?"; http_uri; fast_pattern; content:" Java/"; http_header; pcre:"/^\/\?[a-f0-9]{32}$/U"; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2013975; rev:3; metadata:created_at 2011_11_30, updated_at 2011_11_30;)
` 

Name : **Neosploit Java Exploit Kit request to /? plus hex 32** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2011-11-30

Last modified date : 2011-11-30

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unkown exploit kit jar download"; flow:established,to_server; content:"GET"; http_method; content:".php?"; http_uri; content:"x=MSIE"; http_uri; fast_pattern; content:"&u="; http_uri; content:"&s="; http_uri; content:"&id="; http_uri; content:"&file="; http_uri; content:".jar"; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014568; rev:3; metadata:created_at 2012_04_16, updated_at 2012_04_16;)

# 2014568
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unkown exploit kit jar download"; flow:established,to_server; content:"GET"; http_method; content:".php?"; http_uri; content:"x=MSIE"; http_uri; fast_pattern; content:"&u="; http_uri; content:"&s="; http_uri; content:"&id="; http_uri; content:"&file="; http_uri; content:".jar"; http_uri; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014568; rev:3; metadata:created_at 2012_04_16, updated_at 2012_04_16;)
` 

Name : **Unkown exploit kit jar download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-16

Last modified date : 2012-04-16

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unkown exploit kit pdf download"; flow:established,to_server; content:"GET"; http_method; content:".php?"; http_uri; content:"x=x"; http_uri; fast_pattern; content:"&u="; http_uri; content:"&s="; http_uri; content:"&id="; http_uri; content:"&file="; http_uri; content:".pdf"; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014657; rev:1; metadata:created_at 2012_04_30, updated_at 2012_04_30;)

# 2014657
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unkown exploit kit pdf download"; flow:established,to_server; content:"GET"; http_method; content:".php?"; http_uri; content:"x=x"; http_uri; fast_pattern; content:"&u="; http_uri; content:"&s="; http_uri; content:"&id="; http_uri; content:"&file="; http_uri; content:".pdf"; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014657; rev:1; metadata:created_at 2012_04_30, updated_at 2012_04_30;)
` 

Name : **Unkown exploit kit pdf download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-30

Last modified date : 2012-04-30

Rev version : 1

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unkown exploit kit payload download"; flow:established,to_server; content:"GET"; http_method; content:".php?"; http_uri; content:"x=x"; http_uri; fast_pattern; content:"&u="; http_uri; content:"&s="; http_uri; content:"&id="; http_uri; content:"&spl="; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014658; rev:1; metadata:created_at 2012_04_30, updated_at 2012_04_30;)

# 2014658
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unkown exploit kit payload download"; flow:established,to_server; content:"GET"; http_method; content:".php?"; http_uri; content:"x=x"; http_uri; fast_pattern; content:"&u="; http_uri; content:"&s="; http_uri; content:"&id="; http_uri; content:"&spl="; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014658; rev:1; metadata:created_at 2012_04_30, updated_at 2012_04_30;)
` 

Name : **Unkown exploit kit payload download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-30

Last modified date : 2012-04-30

Rev version : 1

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Redkit Java Exploit request to /24842.jar"; flow:established,to_server; content:"/24842.jar"; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014749; rev:1; metadata:created_at 2012_05_14, updated_at 2012_05_14;)

# 2014749
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Redkit Java Exploit request to /24842.jar"; flow:established,to_server; content:"/24842.jar"; http_uri; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014749; rev:1; metadata:created_at 2012_05_14, updated_at 2012_05_14;)
` 

Name : **Redkit Java Exploit request to /24842.jar** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-14

Last modified date : 2012-05-14

Rev version : 1

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown java_ara Bin Download"; flow:established,to_server; content:"java_ara&name="; http_uri; content:"/forum/"; http_uri; content:".php?"; http_uri; flowbits:isset,ET.http.javaclient.vulnerable; classtype:trojan-activity; sid:2014805; rev:2; metadata:created_at 2012_05_23, updated_at 2012_05_23;)

# 2014805
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Unknown java_ara Bin Download"; flow:established,to_server; content:"java_ara&name="; http_uri; content:"/forum/"; http_uri; content:".php?"; http_uri; flowbits:isset,ET.http.javaclient.vulnerable; classtype:trojan-activity; sid:2014805; rev:2; metadata:created_at 2012_05_23, updated_at 2012_05_23;)
` 

Name : **Unknown java_ara Bin Download** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-23

Last modified date : 2012-05-23

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Incognito Exploit Kit landing page request to images.php?t=4xxxxxxx"; flow:established,to_server; content:"/images.php?t="; http_uri; urilen:22; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014641; rev:4; metadata:created_at 2012_04_26, updated_at 2012_04_26;)

# 2014641
`#alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Incognito Exploit Kit landing page request to images.php?t=4xxxxxxx"; flow:established,to_server; content:"/images.php?t="; http_uri; urilen:22; flowbits:set,et.exploitkitlanding; metadata: former_category EXPLOIT_KIT; classtype:trojan-activity; sid:2014641; rev:4; metadata:created_at 2012_04_26, updated_at 2012_04_26;)
` 

Name : **Incognito Exploit Kit landing page request to images.php?t=4xxxxxxx** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-04-26

Last modified date : 2012-04-26

Rev version : 4

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET CURRENT_EVENTS FedEX Spam Inbound"; flow:established,to_server; content:"name=|22|FEDEX"; nocase; content:".zip|22|"; within:47; nocase; pcre:"/name=\x22FEDEX(\s|_|\-)?[a-z0-9\-_\.\s]{0,42}\.zip\x22/i"; classtype:trojan-activity; sid:2014827; rev:2; metadata:created_at 2012_05_30, updated_at 2012_05_30;)

# 2014827
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET CURRENT_EVENTS FedEX Spam Inbound"; flow:established,to_server; content:"name=|22|FEDEX"; nocase; content:".zip|22|"; within:47; nocase; pcre:"/name=\x22FEDEX(\s|_|\-)?[a-z0-9\-_\.\s]{0,42}\.zip\x22/i"; classtype:trojan-activity; sid:2014827; rev:2; metadata:created_at 2012_05_30, updated_at 2012_05_30;)
` 

Name : **FedEX Spam Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-30

Last modified date : 2012-05-30

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET CURRENT_EVENTS UPS Spam Inbound"; flow:established,to_server; content:"name=|22|"; nocase; content:"UPS"; nocase; within:11; content:".zip|22|"; within:74; nocase; pcre:"/name=\x22([a-z_]{0,8})?UPS(\s|_|\-)?[a-z0-9\-_\.\s]{0,69}\.zip\x22/i"; metadata: former_category CURRENT_EVENTS; classtype:trojan-activity; sid:2014828; rev:2; metadata:created_at 2012_05_30, updated_at 2017_12_11;)

# 2014828
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET CURRENT_EVENTS UPS Spam Inbound"; flow:established,to_server; content:"name=|22|"; nocase; content:"UPS"; nocase; within:11; content:".zip|22|"; within:74; nocase; pcre:"/name=\x22([a-z_]{0,8})?UPS(\s|_|\-)?[a-z0-9\-_\.\s]{0,69}\.zip\x22/i"; metadata: former_category CURRENT_EVENTS; classtype:trojan-activity; sid:2014828; rev:2; metadata:created_at 2012_05_30, updated_at 2017_12_11;)
` 

Name : **UPS Spam Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-30

Last modified date : 2017-12-11

Rev version : 2

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET CURRENT_EVENTS Post Express Spam Inbound"; flow:established,to_server; content:"name=|22|Post_Express_Label_"; nocase; content:".zip|22|"; within:15; nocase; pcre:"/name=\x22Post_Express_Label_[a-z0-9\-_\.\s]{0,10}\.zip\x22/i"; classtype:trojan-activity; sid:2014829; rev:1; metadata:created_at 2012_05_30, updated_at 2012_05_30;)

# 2014829
`#alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"ET CURRENT_EVENTS Post Express Spam Inbound"; flow:established,to_server; content:"name=|22|Post_Express_Label_"; nocase; content:".zip|22|"; within:15; nocase; pcre:"/name=\x22Post_Express_Label_[a-z0-9\-_\.\s]{0,10}\.zip\x22/i"; classtype:trojan-activity; sid:2014829; rev:1; metadata:created_at 2012_05_30, updated_at 2012_05_30;)
` 

Name : **Post Express Spam Inbound** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : trojan-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2012-05-30

Last modified date : 2012-05-30

Rev version : 1

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET CURRENT_EVENTS webshell used In timthumb attacks GIF98a 16129xX with PHP"; flow:to_client,established; file_data; content:"|0d 0a 0d 0a|GIF89a|01 3f|"; content:"<?"; within:720; reference:url,blog.sucuri.net/2012/05/list-of-domains-hosting-webshells-for-timthumb-attacks.html; classtype:web-application-attack; sid:2014848; rev:3; metadata:created_at 2012_06_01, updated_at 2012_06_01;)

# 2014848
`#alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET CURRENT_EVENTS webshell used In timthumb attacks GIF98a 16129xX with PHP"; flow:to_client,established; file_data; content:"|0d 0a 0d 0a|GIF89a|01 3f|"; content:"<?"; within:720; reference:url,blog.sucuri.net/2012/05/list-of-domains-hosting-webshells-for-timthumb-attacks.html; classtype:web-application-attack; sid:2014848; rev:3; metadata:created_at 2012_06_01, updated_at 2012_06_01;)
` 

Name : **webshell used In timthumb attacks GIF98a 16129xX with PHP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,blog.sucuri.net/2012/05/list-of-domains-hosting-webshells-for-timthumb-attacks.html

CVE reference : Not defined

Creation date : 2012-06-01

Last modified date : 2012-06-01

Rev version : 3

Category : CURRENT_EVENTS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Possible Sakura Exploit Kit Version 1.1 document.write Fake 404 - Landing Page"; flow:established,to_client; content:"document.write(|22|404|22 3B|"; metadata: former_category EXPLOIT_KIT; reference:url,blog.spiderlabs.com/2012/05/sakura-exploit-kit-11.html; classtype:trojan-activity; sid:2014852; rev:3; metadata:created_at 2012_06_04, updated_at 2012_06_04;)

# 2014852
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Possible Sakura Exploit Kit Version 1.1 document.write Fake 404 - Landing Page"; flow:established,to_client; content:"document.write(|22|404|22 3B|"; metadata: former_category EXPLOIT_KIT; reference:url,blog.spiderlabs.com/2012/05/sakura-exploit-kit-11.html; classtype:trojan-activity; sid:2014852; rev:3; metadata:created_at 2012_06_04, updated_at 2012_06_04;)
` 

Name : **Possible Sakura Exploit Kit Version 1.1 document.write Fake 404 - Landing Page** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,blog.spiderlabs.com/2012/05/sakura-exploit-kit-11.html

CVE reference : Not defined

Creation date : 2012-06-04

Last modified date : 2012-06-04

Rev version : 3

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Sakura Exploit Kit Version 1.1 Archive Request"; flow:established,to_server; content:"/getfile.php?i="; http_uri; content:"&key="; http_uri; pcre:"/\x2Fgetfile\x2Ephp\x3Fi\x3D[0-9]\x26key\x3D[a-f0-9]{32}$/Ui"; metadata: former_category EXPLOIT_KIT; reference:url,blog.spiderlabs.com/2012/05/sakura-exploit-kit-11.html; classtype:trojan-activity; sid:2014851; rev:2; metadata:created_at 2012_06_04, updated_at 2012_06_04;)

# 2014851
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Sakura Exploit Kit Version 1.1 Archive Request"; flow:established,to_server; content:"/getfile.php?i="; http_uri; content:"&key="; http_uri; pcre:"/\x2Fgetfile\x2Ephp\x3Fi\x3D[0-9]\x26key\x3D[a-f0-9]{32}$/Ui"; metadata: former_category EXPLOIT_KIT; reference:url,blog.spiderlabs.com/2012/05/sakura-exploit-kit-11.html; classtype:trojan-activity; sid:2014851; rev:2; metadata:created_at 2012_06_04, updated_at 2012_06_04;)
` 

Name : **Sakura Exploit Kit Version 1.1 Archive Request** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : exploit-kit

URL reference : url,blog.spiderlabs.com/2012/05/sakura-exploit-kit-11.html

CVE reference : Not defined

Creation date : 2012-06-04

Last modified date : 2012-06-04

Rev version : 2

Category : EXPLOIT_KIT

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Redirect to driveby sid=mix"; flow:to_server,established; content:"/go.php?sid=mix"; http_uri; classtype:bad-unknown; sid:2014866; rev:2; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, tag DriveBy, signature_severity Major, created_at 2012_06_07, updated_at 2016_07_01;)

