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



alert tcp $EXTERNAL_NET any -> $HOME_NET 912 (msg:"ET SCADA RealWin SCADA System Buffer Overflow"; flow:established,to_server; content:"|64 12 54 6a|"; depth:4; content:"|00 00 00 f4 1f 00 00|"; distance:1; within:7; isdataat:220; content:!"|0a|"; distance:0; pcre:"/\x64\x12\x54\x6a[\x20\x10\x02]\x00\x00\x00\xf4\x1f\x00\x00/"; reference:url,www.exploit-db.com/exploits/15337/; classtype:attempted-dos; sid:2011976; rev:1; metadata:created_at 2010_11_24, updated_at 2010_11_24;)

# 2011976
`alert tcp $EXTERNAL_NET any -> $HOME_NET 912 (msg:"ET SCADA RealWin SCADA System Buffer Overflow"; flow:established,to_server; content:"|64 12 54 6a|"; depth:4; content:"|00 00 00 f4 1f 00 00|"; distance:1; within:7; isdataat:220; content:!"|0a|"; distance:0; pcre:"/\x64\x12\x54\x6a[\x20\x10\x02]\x00\x00\x00\xf4\x1f\x00\x00/"; reference:url,www.exploit-db.com/exploits/15337/; classtype:attempted-dos; sid:2011976; rev:1; metadata:created_at 2010_11_24, updated_at 2010_11_24;)
` 

Name : **RealWin SCADA System Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,www.exploit-db.com/exploits/15337/

CVE reference : Not defined

Creation date : 2010-11-24

Last modified date : 2010-11-24

Rev version : 1

Category : SCADA

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 910 (msg:"ET SCADA DATAC RealWin SCADA Server Buffer Overflow"; flow:established,to_server; content:"|10 23 54 67 00 08 00 00|"; depth:8; content:"|e3 77 0a 00 05 00 04 00 00 00|"; distance:0; within:10; isdataat:744,relative; content:!"|0a|"; within:744; reference:url,www.securityfocus.com/bid/31418; reference:cve,2008-4322; reference:url,secunia.com/advisories/32055; classtype:attempted-user; sid:2012096; rev:1; metadata:created_at 2010_12_23, updated_at 2010_12_23;)

# 2012096
`alert tcp $EXTERNAL_NET any -> $HOME_NET 910 (msg:"ET SCADA DATAC RealWin SCADA Server Buffer Overflow"; flow:established,to_server; content:"|10 23 54 67 00 08 00 00|"; depth:8; content:"|e3 77 0a 00 05 00 04 00 00 00|"; distance:0; within:10; isdataat:744,relative; content:!"|0a|"; within:744; reference:url,www.securityfocus.com/bid/31418; reference:cve,2008-4322; reference:url,secunia.com/advisories/32055; classtype:attempted-user; sid:2012096; rev:1; metadata:created_at 2010_12_23, updated_at 2010_12_23;)
` 

Name : **DATAC RealWin SCADA Server Buffer Overflow** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,www.securityfocus.com/bid/31418|cve,2008-4322|url,secunia.com/advisories/32055

CVE reference : Not defined

Creation date : 2010-12-23

Last modified date : 2010-12-23

Rev version : 1

Category : SCADA

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA ICONICS WebHMI ActiveX Stack Overflow"; flow:to_client,established; content:"D25FCAFC-F795-4609-89BB-5F78B4ACAF2C"; nocase; content:"SetActiveXGUID"; distance:0; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*D25FCAFC-F795-4609-89BB-5F78B4ACAF2C/si"; reference:url,www.security-assessment.com/files/documents/advisory/ICONICS_WebHMI.pdf; reference:url,www.exploit-db.com/exploits/17240/; classtype:attempted-user; sid:2012787; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_05_04, updated_at 2016_07_01;)

# 2012787
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA ICONICS WebHMI ActiveX Stack Overflow"; flow:to_client,established; content:"D25FCAFC-F795-4609-89BB-5F78B4ACAF2C"; nocase; content:"SetActiveXGUID"; distance:0; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*D25FCAFC-F795-4609-89BB-5F78B4ACAF2C/si"; reference:url,www.security-assessment.com/files/documents/advisory/ICONICS_WebHMI.pdf; reference:url,www.exploit-db.com/exploits/17240/; classtype:attempted-user; sid:2012787; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_05_04, updated_at 2016_07_01;)
` 

Name : **ICONICS WebHMI ActiveX Stack Overflow** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,www.security-assessment.com/files/documents/advisory/ICONICS_WebHMI.pdf|url,www.exploit-db.com/exploits/17240/

CVE reference : Not defined

Creation date : 2011-05-04

Last modified date : 2016-07-01

Rev version : 4

Category : SCADA

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 7580 (msg:"ET SCADA Siemens FactoryLink 8 CSService Logging  Buffer Overflow Vulnerability"; flow:established,to_server; content:"CSService"; nocase; isdataat:1000,relative; content:!"|0A|"; within:1000; reference:url,packetstormsecurity.org/files/view/102579/factorylink_csservice.rb.txt; classtype:denial-of-service; sid:2013120; rev:1; metadata:created_at 2011_06_27, updated_at 2011_06_27;)

# 2013120
`alert tcp $EXTERNAL_NET any -> $HOME_NET 7580 (msg:"ET SCADA Siemens FactoryLink 8 CSService Logging  Buffer Overflow Vulnerability"; flow:established,to_server; content:"CSService"; nocase; isdataat:1000,relative; content:!"|0A|"; within:1000; reference:url,packetstormsecurity.org/files/view/102579/factorylink_csservice.rb.txt; classtype:denial-of-service; sid:2013120; rev:1; metadata:created_at 2011_06_27, updated_at 2011_06_27;)
` 

Name : **Siemens FactoryLink 8 CSService Logging  Buffer Overflow Vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url,packetstormsecurity.org/files/view/102579/factorylink_csservice.rb.txt

CVE reference : Not defined

Creation date : 2011-06-27

Last modified date : 2011-06-27

Rev version : 1

Category : SCADA

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA Sunway ForceControl Activex Control Vulnerability"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"BD9E5104-2F20-4A9F-AB14-82D558FF374E"; nocase; distance:0; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*BD9E5104-2F20-4A9F-AB14-82D558FF374E/si"; reference:bugtraq,49747; classtype:attempted-user; sid:2013735; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)

# 2013735
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA Sunway ForceControl Activex Control Vulnerability"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"BD9E5104-2F20-4A9F-AB14-82D558FF374E"; nocase; distance:0; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*BD9E5104-2F20-4A9F-AB14-82D558FF374E/si"; reference:bugtraq,49747; classtype:attempted-user; sid:2013735; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)
` 

Name : **Sunway ForceControl Activex Control Vulnerability** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : bugtraq,49747

CVE reference : Not defined

Creation date : 2011-10-04

Last modified date : 2016-07-01

Rev version : 3

Category : SCADA

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PcVue Activex Control Insecure method (GetExtendedColor)"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"2BBD45A5-28AE-11D1-ACAC-0800170967D9"; nocase; distance:0; content:".GetExtendedColor"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*2BBD45A5-28AE-11D1-ACAC-0800170967D9/si"; reference:url,exploit-db.com/exploits/17896; classtype:attempted-user; sid:2013734; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)

# 2013734
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PcVue Activex Control Insecure method (GetExtendedColor)"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"2BBD45A5-28AE-11D1-ACAC-0800170967D9"; nocase; distance:0; content:".GetExtendedColor"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*2BBD45A5-28AE-11D1-ACAC-0800170967D9/si"; reference:url,exploit-db.com/exploits/17896; classtype:attempted-user; sid:2013734; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)
` 

Name : **PcVue Activex Control Insecure method (GetExtendedColor)** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,exploit-db.com/exploits/17896

CVE reference : Not defined

Creation date : 2011-10-04

Last modified date : 2016-07-01

Rev version : 3

Category : SCADA

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PcVue Activex Control Insecure method (LoadObject)"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"2BBD45A5-28AE-11D1-ACAC-0800170967D9"; nocase; distance:0; content:".LoadObject"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*2BBD45A5-28AE-11D1-ACAC-0800170967D9/si"; reference:url,exploit-db.com/exploits/17896; classtype:attempted-user; sid:2013733; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)

# 2013733
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PcVue Activex Control Insecure method (LoadObject)"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"2BBD45A5-28AE-11D1-ACAC-0800170967D9"; nocase; distance:0; content:".LoadObject"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*2BBD45A5-28AE-11D1-ACAC-0800170967D9/si"; reference:url,exploit-db.com/exploits/17896; classtype:attempted-user; sid:2013733; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)
` 

Name : **PcVue Activex Control Insecure method (LoadObject)** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,exploit-db.com/exploits/17896

CVE reference : Not defined

Creation date : 2011-10-04

Last modified date : 2016-07-01

Rev version : 3

Category : SCADA

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PcVue Activex Control Insecure method (SaveObject)"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"2BBD45A5-28AE-11D1-ACAC-0800170967D9"; nocase; distance:0; content:".SaveObject"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*2BBD45A5-28AE-11D1-ACAC-0800170967D9/si"; reference:url,exploit-db.com/exploits/17896; classtype:attempted-user; sid:2013732; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)

# 2013732
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PcVue Activex Control Insecure method (SaveObject)"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"2BBD45A5-28AE-11D1-ACAC-0800170967D9"; nocase; distance:0; content:".SaveObject"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*2BBD45A5-28AE-11D1-ACAC-0800170967D9/si"; reference:url,exploit-db.com/exploits/17896; classtype:attempted-user; sid:2013732; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)
` 

Name : **PcVue Activex Control Insecure method (SaveObject)** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,exploit-db.com/exploits/17896

CVE reference : Not defined

Creation date : 2011-10-04

Last modified date : 2016-07-01

Rev version : 3

Category : SCADA

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PROMOTIC ActiveX Control Insecure method (SaveCfg)"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"02000002-9DFA-4B37-ABE9-1929F4BCDEA2"; nocase; distance:0; content:".SaveCfg"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*02000002-9DFA-4B37-ABE9-1929F4BCDEA2/si"; reference:url,aluigi.altervista.org/adv/promotic_1-adv.txt; classtype:attempted-user; sid:2013878; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_11_08, updated_at 2016_07_01;)

# 2013878
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PROMOTIC ActiveX Control Insecure method (SaveCfg)"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"02000002-9DFA-4B37-ABE9-1929F4BCDEA2"; nocase; distance:0; content:".SaveCfg"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*02000002-9DFA-4B37-ABE9-1929F4BCDEA2/si"; reference:url,aluigi.altervista.org/adv/promotic_1-adv.txt; classtype:attempted-user; sid:2013878; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_11_08, updated_at 2016_07_01;)
` 

Name : **PROMOTIC ActiveX Control Insecure method (SaveCfg)** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,aluigi.altervista.org/adv/promotic_1-adv.txt

CVE reference : Not defined

Creation date : 2011-11-08

Last modified date : 2016-07-01

Rev version : 4

Category : SCADA

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PROMOTIC ActiveX Control Insecure method (AddTrend)"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"02000002-9DFA-4B37-ABE9-1929F4BCDEA2"; nocase; distance:0; content:".AddTrend"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*02000002-9DFA-4B37-ABE9-1929F4BCDEA2/si"; reference:url,aluigi.altervista.org/adv/promotic_1-adv.txt; classtype:attempted-user; sid:2013879; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_11_08, updated_at 2016_07_01;)

# 2013879
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PROMOTIC ActiveX Control Insecure method (AddTrend)"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"02000002-9DFA-4B37-ABE9-1929F4BCDEA2"; nocase; distance:0; content:".AddTrend"; nocase; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*02000002-9DFA-4B37-ABE9-1929F4BCDEA2/si"; reference:url,aluigi.altervista.org/adv/promotic_1-adv.txt; classtype:attempted-user; sid:2013879; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_11_08, updated_at 2016_07_01;)
` 

Name : **PROMOTIC ActiveX Control Insecure method (AddTrend)** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,aluigi.altervista.org/adv/promotic_1-adv.txt

CVE reference : Not defined

Creation date : 2011-11-08

Last modified date : 2016-07-01

Rev version : 2

Category : SCADA

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA Sunway ForceControl Activex Control Remote Code Execution Vulnerability 2"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"3310FA24-A027-47B3-8C49-1091077317E9"; nocase; distance:0; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*3310FA24-A027-47B3-8C49-1091077317E9/si"; reference:bugtraq,49747; classtype:attempted-user; sid:2013736; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)

# 2013736
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA Sunway ForceControl Activex Control Remote Code Execution Vulnerability 2"; flow:to_client,established; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"3310FA24-A027-47B3-8C49-1091077317E9"; nocase; distance:0; pcre:"/<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*3310FA24-A027-47B3-8C49-1091077317E9/si"; reference:bugtraq,49747; classtype:attempted-user; sid:2013736; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)
` 

Name : **Sunway ForceControl Activex Control Remote Code Execution Vulnerability 2** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : bugtraq,49747

CVE reference : Not defined

Creation date : 2011-10-04

Last modified date : 2016-07-01

Rev version : 4

Category : SCADA

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PcVue Activex Control Insecure method (AddPage)"; flow:to_client,established; file_data; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"083B40D3-CCBA-11D2-AFE0-00C04F7993D6"; nocase; distance:0; content:".AddPage"; nocase; content:"<OBJECT"; nocase; pcre:"/^[^>]*?classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*?083B40D3-CCBA-11D2-AFE0-00C04F7993D6/Rsi"; reference:url,exploit-db.com/exploits/17896; classtype:attempted-user; sid:2013730; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)

# 2013730
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PcVue Activex Control Insecure method (AddPage)"; flow:to_client,established; file_data; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"CLSID"; nocase; distance:0; content:"083B40D3-CCBA-11D2-AFE0-00C04F7993D6"; nocase; distance:0; content:".AddPage"; nocase; content:"<OBJECT"; nocase; pcre:"/^[^>]*?classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*?083B40D3-CCBA-11D2-AFE0-00C04F7993D6/Rsi"; reference:url,exploit-db.com/exploits/17896; classtype:attempted-user; sid:2013730; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)
` 

Name : **PcVue Activex Control Insecure method (AddPage)** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,exploit-db.com/exploits/17896

CVE reference : Not defined

Creation date : 2011-10-04

Last modified date : 2016-07-01

Rev version : 4

Category : SCADA

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PcVue Activex Control Insecure method (DeletePage)"; flow:to_client,established; file_data; content:"083B40D3-CCBA-11D2-AFE0-00C04F7993D6"; nocase; distance:0; content:".DeletePage"; nocase; content:"<OBJECT"; pcre:"/^[^>]*?classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*083B40D3-CCBA-11D2-AFE0-00C04F7993D6/Rsi"; reference:url,exploit-db.com/exploits/17896; classtype:attempted-user; sid:2013731; rev:5; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)

# 2013731
`alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCADA PcVue Activex Control Insecure method (DeletePage)"; flow:to_client,established; file_data; content:"083B40D3-CCBA-11D2-AFE0-00C04F7993D6"; nocase; distance:0; content:".DeletePage"; nocase; content:"<OBJECT"; pcre:"/^[^>]*?classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*083B40D3-CCBA-11D2-AFE0-00C04F7993D6/Rsi"; reference:url,exploit-db.com/exploits/17896; classtype:attempted-user; sid:2013731; rev:5; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2011_10_04, updated_at 2016_07_01;)
` 

Name : **PcVue Activex Control Insecure method (DeletePage)** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,exploit-db.com/exploits/17896

CVE reference : Not defined

Creation date : 2011-10-04

Last modified date : 2016-07-01

Rev version : 5

Category : SCADA

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 910 (msg:"ET SCADA DATAC RealWin SCADA Server 2 On_FC_CONNECT_FCS_a_FILE Buffer Overflow Vulnerability"; flow:established,to_server; content:"GetFlexMLangIResourceBrowser"; isdataat:1000,relative; content:!"|0A|"; within:1000; reference:url,exploit-db.com/exploits/17417/; classtype:denial-of-service; sid:2013074; rev:2; metadata:created_at 2011_06_21, updated_at 2011_06_21;)

# 2013074
`alert tcp $EXTERNAL_NET any -> $HOME_NET 910 (msg:"ET SCADA DATAC RealWin SCADA Server 2 On_FC_CONNECT_FCS_a_FILE Buffer Overflow Vulnerability"; flow:established,to_server; content:"GetFlexMLangIResourceBrowser"; isdataat:1000,relative; content:!"|0A|"; within:1000; reference:url,exploit-db.com/exploits/17417/; classtype:denial-of-service; sid:2013074; rev:2; metadata:created_at 2011_06_21, updated_at 2011_06_21;)
` 

Name : **DATAC RealWin SCADA Server 2 On_FC_CONNECT_FCS_a_FILE Buffer Overflow Vulnerability** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : url,exploit-db.com/exploits/17417/

CVE reference : Not defined

Creation date : 2011-06-21

Last modified date : 2011-06-21

Rev version : 2

Category : SCADA

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 4444 (msg:"ET SCADA Golden FTP Server PASS Command Remote Buffer Overflow Attempt"; flow:established,to_server; content:"PASS"; nocase; isdataat:1000,relative; content:!"|0A|"; within:1000; reference:bugtraq,45957; classtype:denial-of-service; sid:2013235; rev:2; metadata:created_at 2011_07_08, updated_at 2011_07_08;)

# 2013235
`alert tcp $EXTERNAL_NET any -> $HOME_NET 4444 (msg:"ET SCADA Golden FTP Server PASS Command Remote Buffer Overflow Attempt"; flow:established,to_server; content:"PASS"; nocase; isdataat:1000,relative; content:!"|0A|"; within:1000; reference:bugtraq,45957; classtype:denial-of-service; sid:2013235; rev:2; metadata:created_at 2011_07_08, updated_at 2011_07_08;)
` 

Name : **Golden FTP Server PASS Command Remote Buffer Overflow Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : denial-of-service

URL reference : bugtraq,45957

CVE reference : Not defined

Creation date : 2011-07-08

Last modified date : 2011-07-08

Rev version : 2

Category : SCADA

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET any -> $HOME_NET 20222 (msg:"ET SCADA CitectSCADA ODBC Overflow Attempt"; flow:established,to_server; dsize:4; byte_test:4,>,399,0; reference:cve,2008-2639; reference:url,www.digitalbond.com/index.php/2008/09/08/ids-signature-for-citect-vuln/; reference:url,digitalbond.com/tools/quickdraw/vulnerability-rules; classtype:attempted-user; sid:2008542; rev:8; metadata:created_at 2010_07_30, updated_at 2016_06_07;)

# 2008542
`alert tcp $EXTERNAL_NET any -> $HOME_NET 20222 (msg:"ET SCADA CitectSCADA ODBC Overflow Attempt"; flow:established,to_server; dsize:4; byte_test:4,>,399,0; reference:cve,2008-2639; reference:url,www.digitalbond.com/index.php/2008/09/08/ids-signature-for-citect-vuln/; reference:url,digitalbond.com/tools/quickdraw/vulnerability-rules; classtype:attempted-user; sid:2008542; rev:8; metadata:created_at 2010_07_30, updated_at 2016_06_07;)
` 

Name : **CitectSCADA ODBC Overflow Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : cve,2008-2639|url,www.digitalbond.com/index.php/2008/09/08/ids-signature-for-citect-vuln/|url,digitalbond.com/tools/quickdraw/vulnerability-rules

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-06-07

Rev version : 8

Category : SCADA

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> $HOME_NET 12397 (msg:"ET SCADA SEIG SYSTEM 9 - Remote Code Execution"; flow:established,to_server; content:"|14 60 00 00 66 66 07 00 10 00 00 00 19 00 00 00 00 00 04 00 00 00 60 00|"; depth:24; content:!"|0d|"; distance:0; content:!"|0a|"; distance:0; content:!"|ff|"; content:!"|00|"; distance:0; metadata: former_category SCADA; reference:url,exploit-db.com/exploits/45218/; reference:cve,2013-0657; classtype:attempted-user; sid:2026003; rev:1; metadata:created_at 2018_08_21, updated_at 2018_08_21;)

# 2026003
`alert tcp any any -> $HOME_NET 12397 (msg:"ET SCADA SEIG SYSTEM 9 - Remote Code Execution"; flow:established,to_server; content:"|14 60 00 00 66 66 07 00 10 00 00 00 19 00 00 00 00 00 04 00 00 00 60 00|"; depth:24; content:!"|0d|"; distance:0; content:!"|0a|"; distance:0; content:!"|ff|"; content:!"|00|"; distance:0; metadata: former_category SCADA; reference:url,exploit-db.com/exploits/45218/; reference:cve,2013-0657; classtype:attempted-user; sid:2026003; rev:1; metadata:created_at 2018_08_21, updated_at 2018_08_21;)
` 

Name : **SEIG SYSTEM 9 - Remote Code Execution** 

Attack target : Not defined

Description : This signature will detect an attempt tp exploit a remote code execution vulnerability in Scada SEIG SYSTEM 9

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,exploit-db.com/exploits/45218/|cve,2013-0657

CVE reference : Not defined

Creation date : 2018-08-21

Last modified date : 2018-08-21

Rev version : 1

Category : SCADA

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp any any -> $HOME_NET 27700 (msg:"ET SCADA SEIG Modbus 3.4 - Remote Code Execution"; flow:established,to_server; content:"|42 42 ff ff 07 03 44 00 64|"; fast_pattern; content:"|90 90 90 90 90 90 90 90 90 90|"; distance:0; metadata: former_category SCADA; reference:url,exploit-db.com/exploits/45220/; reference:cve,2013-0662; classtype:attempted-user; sid:2026005; rev:1; metadata:created_at 2018_08_21, updated_at 2018_08_21;)

# 2026005
`alert tcp any any -> $HOME_NET 27700 (msg:"ET SCADA SEIG Modbus 3.4 - Remote Code Execution"; flow:established,to_server; content:"|42 42 ff ff 07 03 44 00 64|"; fast_pattern; content:"|90 90 90 90 90 90 90 90 90 90|"; distance:0; metadata: former_category SCADA; reference:url,exploit-db.com/exploits/45220/; reference:cve,2013-0662; classtype:attempted-user; sid:2026005; rev:1; metadata:created_at 2018_08_21, updated_at 2018_08_21;)
` 

Name : **SEIG Modbus 3.4 - Remote Code Execution** 

Attack target : Not defined

Description : This signature will detect an attempt top exploit a remote code execution vulnerability in SCADA SIEG Modbus 3.4

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,exploit-db.com/exploits/45220/|cve,2013-0662

CVE reference : Not defined

Creation date : 2018-08-21

Last modified date : 2018-08-21

Rev version : 1

Category : SCADA

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



