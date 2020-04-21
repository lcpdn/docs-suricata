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



alert tcp $EXTERNAL_NET any -> $HOME_NET 82 (msg:"ET WEB_SPECIFIC_APPS ClarkConnect Linux proxy.php XSS Attempt"; flow:established,to_server; content:"GET"; content:"script"; nocase; content:"/proxy.php?"; nocase; content:"url="; nocase; pcre:"/\/proxy\.php(\?|.*[\x26\x3B])url=[^&\;\x0D\x0A]*[<>\"\']/i"; reference:url,www.securityfocus.com/bid/37446/info; reference:url,doc.emergingthreats.net/2010602; classtype:web-application-attack; sid:2010602; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2010602
`alert tcp $EXTERNAL_NET any -> $HOME_NET 82 (msg:"ET WEB_SPECIFIC_APPS ClarkConnect Linux proxy.php XSS Attempt"; flow:established,to_server; content:"GET"; content:"script"; nocase; content:"/proxy.php?"; nocase; content:"url="; nocase; pcre:"/\/proxy\.php(\?|.*[\x26\x3B])url=[^&\;\x0D\x0A]*[<>\"\']/i"; reference:url,www.securityfocus.com/bid/37446/info; reference:url,doc.emergingthreats.net/2010602; classtype:web-application-attack; sid:2010602; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **ClarkConnect Linux proxy.php XSS Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.securityfocus.com/bid/37446/info|url,doc.emergingthreats.net/2010602

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS DGNews XSS Attempt -- news.php catid"; flow:established,to_server; uricontent:"/news.php?"; nocase; uricontent:"catid="; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-0693; reference:url,www.securityfocus.com/bid/24201; reference:url,doc.emergingthreats.net/2004585; classtype:web-application-attack; sid:2004585; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004585
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS DGNews XSS Attempt -- news.php catid"; flow:established,to_server; uricontent:"/news.php?"; nocase; uricontent:"catid="; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-0693; reference:url,www.securityfocus.com/bid/24201; reference:url,doc.emergingthreats.net/2004585; classtype:web-application-attack; sid:2004585; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **DGNews XSS Attempt -- news.php catid** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-0693|url,www.securityfocus.com/bid/24201|url,doc.emergingthreats.net/2004585

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS FSphp pathwirte.php FSPHP_LIB Parameter Remote File Inclusion Attempt"; flow:to_server,established; uricontent:"/lib/pathwirte.php?"; nocase; uricontent:"FSPHP_LIB="; nocase; pcre:"/FSPHP_LIB\s*=\s*(https?|ftps?|php)\:\//Ui"; reference:url,osvdb.org/show/osvdb/58317; reference:url,www.milw0rm.com/exploits/9720; reference:url,doc.emergingthreats.net/2010361; classtype:web-application-attack; sid:2010361; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010361
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS FSphp pathwirte.php FSPHP_LIB Parameter Remote File Inclusion Attempt"; flow:to_server,established; uricontent:"/lib/pathwirte.php?"; nocase; uricontent:"FSPHP_LIB="; nocase; pcre:"/FSPHP_LIB\s*=\s*(https?|ftps?|php)\:\//Ui"; reference:url,osvdb.org/show/osvdb/58317; reference:url,www.milw0rm.com/exploits/9720; reference:url,doc.emergingthreats.net/2010361; classtype:web-application-attack; sid:2010361; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **FSphp pathwirte.php FSPHP_LIB Parameter Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,osvdb.org/show/osvdb/58317|url,www.milw0rm.com/exploits/9720|url,doc.emergingthreats.net/2010361

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS JBoss JMX Console Beanshell Deployer .WAR File Upload and Deployment Cross Site Request Forgery Attempt"; flow:established,to_client; content:"/HtmlAdaptor"; nocase; content:"action=invokeOpByName"; nocase; within:25; content:"DeploymentFileRepository"; nocase; within:80; content:"methodName="; nocase; within:25; content:".war"; nocase; distance:0; content:".jsp"; nocase; distance:0; reference:url,www.redteam-pentesting.de/en/publications/jboss/-bridging-the-gap-between-the-enterprise-and-you-or-whos-the-jboss-now; reference:cve,2010-0738; reference:url,doc.emergingthreats.net/2011697; classtype:web-application-attack; sid:2011697; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2011697
`alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS JBoss JMX Console Beanshell Deployer .WAR File Upload and Deployment Cross Site Request Forgery Attempt"; flow:established,to_client; content:"/HtmlAdaptor"; nocase; content:"action=invokeOpByName"; nocase; within:25; content:"DeploymentFileRepository"; nocase; within:80; content:"methodName="; nocase; within:25; content:".war"; nocase; distance:0; content:".jsp"; nocase; distance:0; reference:url,www.redteam-pentesting.de/en/publications/jboss/-bridging-the-gap-between-the-enterprise-and-you-or-whos-the-jboss-now; reference:cve,2010-0738; reference:url,doc.emergingthreats.net/2011697; classtype:web-application-attack; sid:2011697; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **JBoss JMX Console Beanshell Deployer .WAR File Upload and Deployment Cross Site Request Forgery Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.redteam-pentesting.de/en/publications/jboss/-bridging-the-gap-between-the-enterprise-and-you-or-whos-the-jboss-now|cve,2010-0738|url,doc.emergingthreats.net/2011697

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS News Manager ch_readalso.php read_xml_include Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/ch_readalso.php?"; nocase; uricontent:"read_xml_include="; nocase; pcre:"/read_xml_include=\s*(https?|ftps?|php)\:\//Ui"; reference:bugtraq,29251; reference:url,xforce.iss.net/xforce/xfdb/42459; reference:url,milw0rm.com/exploits/5624; reference:url,doc.emergingthreats.net/2010099; classtype:web-application-attack; sid:2010099; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010099
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS News Manager ch_readalso.php read_xml_include Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/ch_readalso.php?"; nocase; uricontent:"read_xml_include="; nocase; pcre:"/read_xml_include=\s*(https?|ftps?|php)\:\//Ui"; reference:bugtraq,29251; reference:url,xforce.iss.net/xforce/xfdb/42459; reference:url,milw0rm.com/exploits/5624; reference:url,doc.emergingthreats.net/2010099; classtype:web-application-attack; sid:2010099; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **News Manager ch_readalso.php read_xml_include Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,29251|url,xforce.iss.net/xforce/xfdb/42459|url,milw0rm.com/exploits/5624|url,doc.emergingthreats.net/2010099

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Nitrotech common.php root Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/common.php?"; nocase; uricontent:"root="; nocase; pcre:"/root=\s*(ftps?|https?|php)\:\//Ui"; reference:url,xforce.iss.net/xforce/xfdb/29904; reference:url,milw0rm.com/exploits/7218; reference:url,doc.emergingthreats.net/2008922; classtype:web-application-attack; sid:2008922; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2008922
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Nitrotech common.php root Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/common.php?"; nocase; uricontent:"root="; nocase; pcre:"/root=\s*(ftps?|https?|php)\:\//Ui"; reference:url,xforce.iss.net/xforce/xfdb/29904; reference:url,milw0rm.com/exploits/7218; reference:url,doc.emergingthreats.net/2008922; classtype:web-application-attack; sid:2008922; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Nitrotech common.php root Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,xforce.iss.net/xforce/xfdb/29904|url,milw0rm.com/exploits/7218|url,doc.emergingthreats.net/2008922

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS NoAH Remote Inclusion Attempt -- mfa_theme.php tpls"; flow:established,to_server; uricontent:"/modules/noevents/templates/mfa_theme.php?"; nocase; uricontent:"tpls["; nocase; reference:cve,CVE-2007-2572; reference:url,www.milw0rm.com/exploits/3861; reference:url,doc.emergingthreats.net/2003694; classtype:web-application-attack; sid:2003694; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003694
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS NoAH Remote Inclusion Attempt -- mfa_theme.php tpls"; flow:established,to_server; uricontent:"/modules/noevents/templates/mfa_theme.php?"; nocase; uricontent:"tpls["; nocase; reference:cve,CVE-2007-2572; reference:url,www.milw0rm.com/exploits/3861; reference:url,doc.emergingthreats.net/2003694; classtype:web-application-attack; sid:2003694; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **NoAH Remote Inclusion Attempt -- mfa_theme.php tpls** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2572|url,www.milw0rm.com/exploits/3861|url,doc.emergingthreats.net/2003694

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Nokia Intellisync Mobile Suite XSS Attempt -- dev_logon.asp username"; flow:established,to_server; uricontent:"/de/pda/dev_logon.asp?"; nocase; uricontent:"username="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2592; reference:url,www.securityfocus.com/archive/1/archive/1/468048/100/0/threaded; reference:url,doc.emergingthreats.net/2003894; classtype:web-application-attack; sid:2003894; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003894
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Nokia Intellisync Mobile Suite XSS Attempt -- dev_logon.asp username"; flow:established,to_server; uricontent:"/de/pda/dev_logon.asp?"; nocase; uricontent:"username="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2592; reference:url,www.securityfocus.com/archive/1/archive/1/468048/100/0/threaded; reference:url,doc.emergingthreats.net/2003894; classtype:web-application-attack; sid:2003894; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Nokia Intellisync Mobile Suite XSS Attempt -- dev_logon.asp username** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2592|url,www.securityfocus.com/archive/1/archive/1/468048/100/0/threaded|url,doc.emergingthreats.net/2003894

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Nokia Intellisync Mobile Suite XSS Attempt -- registerAccount.asp"; flow:established,to_server; uricontent:"/usrmgr/registerAccount.asp?"; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2592; reference:url,www.securityfocus.com/archive/1/archive/1/468048/100/0/threaded; reference:url,doc.emergingthreats.net/2003895; classtype:web-application-attack; sid:2003895; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003895
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Nokia Intellisync Mobile Suite XSS Attempt -- registerAccount.asp"; flow:established,to_server; uricontent:"/usrmgr/registerAccount.asp?"; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2592; reference:url,www.securityfocus.com/archive/1/archive/1/468048/100/0/threaded; reference:url,doc.emergingthreats.net/2003895; classtype:web-application-attack; sid:2003895; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Nokia Intellisync Mobile Suite XSS Attempt -- registerAccount.asp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2592|url,www.securityfocus.com/archive/1/archive/1/468048/100/0/threaded|url,doc.emergingthreats.net/2003895

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Nokia Intellisync Mobile Suite XSS Attempt -- create_account.asp"; flow:established,to_server; uricontent:"/de/create_account.asp?"; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2592; reference:url,www.securityfocus.com/archive/1/archive/1/468048/100/0/threaded; reference:url,doc.emergingthreats.net/2003896; classtype:web-application-attack; sid:2003896; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003896
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Nokia Intellisync Mobile Suite XSS Attempt -- create_account.asp"; flow:established,to_server; uricontent:"/de/create_account.asp?"; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2592; reference:url,www.securityfocus.com/archive/1/archive/1/468048/100/0/threaded; reference:url,doc.emergingthreats.net/2003896; classtype:web-application-attack; sid:2003896; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Nokia Intellisync Mobile Suite XSS Attempt -- create_account.asp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2592|url,www.securityfocus.com/archive/1/archive/1/468048/100/0/threaded|url,doc.emergingthreats.net/2003896

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ODARS resource_categories_view.php CLASSES_ROOT parameter Remote file inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/resource_categories_view.php?"; nocase; uricontent:"CLASSES_ROOT="; nocase; pcre:"/CLASSES_ROOT=\s*(https?|ftps?|php)\:\//Ui"; reference:url,secunia.com/advisories/30784/; reference:url,milw0rm.com/exploits/5906; reference:url,doc.emergingthreats.net/2009333; classtype:web-application-attack; sid:2009333; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009333
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ODARS resource_categories_view.php CLASSES_ROOT parameter Remote file inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/resource_categories_view.php?"; nocase; uricontent:"CLASSES_ROOT="; nocase; pcre:"/CLASSES_ROOT=\s*(https?|ftps?|php)\:\//Ui"; reference:url,secunia.com/advisories/30784/; reference:url,milw0rm.com/exploits/5906; reference:url,doc.emergingthreats.net/2009333; classtype:web-application-attack; sid:2009333; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ODARS resource_categories_view.php CLASSES_ROOT parameter Remote file inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,secunia.com/advisories/30784/|url,milw0rm.com/exploits/5906|url,doc.emergingthreats.net/2009333

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS OSTicket Remote Code Execution Attempt"; flow: established,from_client; uricontent:"/osticket/include"; nocase; pcre:"/.*\[.*\].*\;/U"; reference:url,secunia.com/advisories/15216; reference:url,www.gulftech.org/?node=research&article_id=00071-05022005; reference:cve,CAN-2005-1438; reference:cve,CAN-2005-1439; reference:url,doc.emergingthreats.net/bin/view/Main/2002702; classtype:web-application-attack; sid:2002702; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002702
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS OSTicket Remote Code Execution Attempt"; flow: established,from_client; uricontent:"/osticket/include"; nocase; pcre:"/.*\[.*\].*\;/U"; reference:url,secunia.com/advisories/15216; reference:url,www.gulftech.org/?node=research&article_id=00071-05022005; reference:cve,CAN-2005-1438; reference:cve,CAN-2005-1439; reference:url,doc.emergingthreats.net/bin/view/Main/2002702; classtype:web-application-attack; sid:2002702; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **OSTicket Remote Code Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,secunia.com/advisories/15216|url,www.gulftech.org/?node=research&article_id=00071-05022005|cve,CAN-2005-1438|cve,CAN-2005-1439|url,doc.emergingthreats.net/bin/view/Main/2002702

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Open Translation Engine Remote Inclusion Attempt -- header.php ote_home"; flow:established,to_server; uricontent:"/skins/header.php?"; nocase; uricontent:"ote_home="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2676; reference:url,www.milw0rm.com/exploits/3838; reference:url,doc.emergingthreats.net/2003741; classtype:web-application-attack; sid:2003741; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003741
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Open Translation Engine Remote Inclusion Attempt -- header.php ote_home"; flow:established,to_server; uricontent:"/skins/header.php?"; nocase; uricontent:"ote_home="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2676; reference:url,www.milw0rm.com/exploits/3838; reference:url,doc.emergingthreats.net/2003741; classtype:web-application-attack; sid:2003741; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Open Translation Engine Remote Inclusion Attempt -- header.php ote_home** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2676|url,www.milw0rm.com/exploits/3838|url,doc.emergingthreats.net/2003741

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Open Translation Engine (OTE) XSS Attempt -- header.php ote_home"; flow:established,to_server; uricontent:"/skins/header.php?"; nocase; uricontent:"ote_home="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2676; reference:url,www.milw0rm.com/exploits/3838; reference:url,doc.emergingthreats.net/2003878; classtype:web-application-attack; sid:2003878; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003878
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Open Translation Engine (OTE) XSS Attempt -- header.php ote_home"; flow:established,to_server; uricontent:"/skins/header.php?"; nocase; uricontent:"ote_home="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2676; reference:url,www.milw0rm.com/exploits/3838; reference:url,doc.emergingthreats.net/2003878; classtype:web-application-attack; sid:2003878; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Open Translation Engine (OTE) XSS Attempt -- header.php ote_home** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2676|url,www.milw0rm.com/exploits/3838|url,doc.emergingthreats.net/2003878

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS openEngine filepool.php oe_classpath parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/filepool.php?"; nocase; uricontent:"oe_classpath="; nocase; pcre:"/oe_classpath=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,31423; reference:url,milw0rm.com/exploits/6585; reference:url,doc.emergingthreats.net/2009164; classtype:web-application-attack; sid:2009164; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009164
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS openEngine filepool.php oe_classpath parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/filepool.php?"; nocase; uricontent:"oe_classpath="; nocase; pcre:"/oe_classpath=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,31423; reference:url,milw0rm.com/exploits/6585; reference:url,doc.emergingthreats.net/2009164; classtype:web-application-attack; sid:2009164; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **openEngine filepool.php oe_classpath parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,31423|url,milw0rm.com/exploits/6585|url,doc.emergingthreats.net/2009164

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Orlando CMS classes init.php GLOBALS Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/modules/core/logger/init.php?"; nocase; uricontent:"GLOBALS[preloc]="; nocase; pcre:"/GLOBALS\[preloc\]=\s*(https?|ftps?|php)\:\//Ui"; reference:bugtraq,29820; reference:url,milw0rm.com/exploits/5864; reference:url,doc.emergingthreats.net/2009459; classtype:web-application-attack; sid:2009459; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009459
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Orlando CMS classes init.php GLOBALS Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/modules/core/logger/init.php?"; nocase; uricontent:"GLOBALS[preloc]="; nocase; pcre:"/GLOBALS\[preloc\]=\s*(https?|ftps?|php)\:\//Ui"; reference:bugtraq,29820; reference:url,milw0rm.com/exploits/5864; reference:url,doc.emergingthreats.net/2009459; classtype:web-application-attack; sid:2009459; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Orlando CMS classes init.php GLOBALS Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,29820|url,milw0rm.com/exploits/5864|url,doc.emergingthreats.net/2009459

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Orlando CMS newscat.php GLOBALS Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/newscat.php?"; nocase; uricontent:"GLOBALS[preloc]="; nocase; pcre:"/GLOBALS\[preloc\]=\s*(https?|ftps?|php)\:\//Ui"; reference:bugtraq,29820; reference:url,milw0rm.com/exploits/5864; reference:url,doc.emergingthreats.net/2009460; classtype:web-application-attack; sid:2009460; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009460
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Orlando CMS newscat.php GLOBALS Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/newscat.php?"; nocase; uricontent:"GLOBALS[preloc]="; nocase; pcre:"/GLOBALS\[preloc\]=\s*(https?|ftps?|php)\:\//Ui"; reference:bugtraq,29820; reference:url,milw0rm.com/exploits/5864; reference:url,doc.emergingthreats.net/2009460; classtype:web-application-attack; sid:2009460; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Orlando CMS newscat.php GLOBALS Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,29820|url,milw0rm.com/exploits/5864|url,doc.emergingthreats.net/2009460

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006528; classtype:web-application-attack; sid:2006528; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006528
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006528; classtype:web-application-attack; sid:2006528; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Client_ID SELECT** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006528

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006529; classtype:web-application-attack; sid:2006529; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006529
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006529; classtype:web-application-attack; sid:2006529; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Client_ID UNION SELECT** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006529

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006530; classtype:web-application-attack; sid:2006530; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006530
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006530; classtype:web-application-attack; sid:2006530; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Client_ID INSERT** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006530

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006531; classtype:web-application-attack; sid:2006531; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006531
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006531; classtype:web-application-attack; sid:2006531; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Client_ID DELETE** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006531

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"ASCII"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006532; classtype:web-application-attack; sid:2006532; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006532
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"ASCII"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006532; classtype:web-application-attack; sid:2006532; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Client_ID ASCII** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006532

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"UPDATE"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006533; classtype:web-application-attack; sid:2006533; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006533
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Client_ID UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Client_ID="; nocase; uricontent:"UPDATE"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006533; classtype:web-application-attack; sid:2006533; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Client_ID UPDATE** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006533

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006534; classtype:web-application-attack; sid:2006534; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006534
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006534; classtype:web-application-attack; sid:2006534; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Invoice_ID SELECT** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006534

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006535; classtype:web-application-attack; sid:2006535; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006535
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006535; classtype:web-application-attack; sid:2006535; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Invoice_ID UNION SELECT** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006535

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006536; classtype:web-application-attack; sid:2006536; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006536
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006536; classtype:web-application-attack; sid:2006536; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Invoice_ID INSERT** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006536

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006537; classtype:web-application-attack; sid:2006537; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006537
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006537; classtype:web-application-attack; sid:2006537; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Invoice_ID DELETE** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006537

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"ASCII"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006538; classtype:web-application-attack; sid:2006538; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006538
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"ASCII"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006538; classtype:web-application-attack; sid:2006538; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Invoice_ID ASCII** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006538

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"UPDATE"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006539; classtype:web-application-attack; sid:2006539; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006539
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Invoice_ID UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Invoice_ID="; nocase; uricontent:"UPDATE"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006539; classtype:web-application-attack; sid:2006539; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Invoice_ID UPDATE** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006539

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006540; classtype:web-application-attack; sid:2006540; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006540
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006540; classtype:web-application-attack; sid:2006540; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Vendor_ID SELECT** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006540

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006541; classtype:web-application-attack; sid:2006541; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006541
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006541; classtype:web-application-attack; sid:2006541; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Vendor_ID UNION SELECT** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006541

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006542; classtype:web-application-attack; sid:2006542; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006542
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006542; classtype:web-application-attack; sid:2006542; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Vendor_ID INSERT** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006542

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006543; classtype:web-application-attack; sid:2006543; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006543
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006543; classtype:web-application-attack; sid:2006543; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Vendor_ID DELETE** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006543

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"ASCII"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006544; classtype:web-application-attack; sid:2006544; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006544
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"ASCII"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006544; classtype:web-application-attack; sid:2006544; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Vendor_ID ASCII** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006544

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"UPDATE"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006545; classtype:web-application-attack; sid:2006545; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2006545
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPAccounts SQL Injection Attempt -- index.php Vendor_ID UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"Vendor_ID="; nocase; uricontent:"UPDATE"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-3345; reference:url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html; reference:url,doc.emergingthreats.net/2006545; classtype:web-application-attack; sid:2006545; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPAccounts SQL Injection Attempt -- index.php Vendor_ID UPDATE** 

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

URL reference : cve,CVE-2007-3345|url,pridels-team.blogspot.com/2007/06/phpaccounts-vuln.html|url,doc.emergingthreats.net/2006545

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPauction GPL converter.inc.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/converter.inc.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(ftps?|https?|php)\://Ui"; reference:url,vupen.com/english/advisories/2008/0908; reference:bugtraq,28284; reference:url,milw0rm.com/exploits/5266; reference:url,doc.emergingthreats.net/2009871; classtype:web-application-attack; sid:2009871; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009871
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPauction GPL converter.inc.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/converter.inc.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(ftps?|https?|php)\://Ui"; reference:url,vupen.com/english/advisories/2008/0908; reference:bugtraq,28284; reference:url,milw0rm.com/exploits/5266; reference:url,doc.emergingthreats.net/2009871; classtype:web-application-attack; sid:2009871; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPauction GPL converter.inc.php include_path Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,vupen.com/english/advisories/2008/0908|bugtraq,28284|url,milw0rm.com/exploits/5266|url,doc.emergingthreats.net/2009871

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPauction GPL messages.inc.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/messages.inc.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(ftps?|https?|php)\://Ui"; reference:url,vupen.com/english/advisories/2008/0908; reference:bugtraq,28284; reference:url,milw0rm.com/exploits/5266; reference:url,doc.emergingthreats.net/2009872; classtype:web-application-attack; sid:2009872; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009872
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPauction GPL messages.inc.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/messages.inc.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(ftps?|https?|php)\://Ui"; reference:url,vupen.com/english/advisories/2008/0908; reference:bugtraq,28284; reference:url,milw0rm.com/exploits/5266; reference:url,doc.emergingthreats.net/2009872; classtype:web-application-attack; sid:2009872; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPauction GPL messages.inc.php include_path Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,vupen.com/english/advisories/2008/0908|bugtraq,28284|url,milw0rm.com/exploits/5266|url,doc.emergingthreats.net/2009872

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPauction GPL settings.inc.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/settings.inc.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(ftps?|https?|php)\://Ui"; reference:url,vupen.com/english/advisories/2008/0908; reference:bugtraq,28284; reference:url,milw0rm.com/exploits/5266; reference:url,doc.emergingthreats.net/2009873; classtype:web-application-attack; sid:2009873; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009873
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPauction GPL settings.inc.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/settings.inc.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(ftps?|https?|php)\://Ui"; reference:url,vupen.com/english/advisories/2008/0908; reference:bugtraq,28284; reference:url,milw0rm.com/exploits/5266; reference:url,doc.emergingthreats.net/2009873; classtype:web-application-attack; sid:2009873; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPauction GPL settings.inc.php include_path Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,vupen.com/english/advisories/2008/0908|bugtraq,28284|url,milw0rm.com/exploits/5266|url,doc.emergingthreats.net/2009873

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS XSS Possible Arbitrary Scripting Code Attack in phpBB (private message)"; flow: established,from_server; content:"privmsg.php"; pcre:"/\<a href="[^"]*(script|about|applet|activex|chrome)\s*\:/i"; reference:url,www.securitytracker.com/alerts/2005/May/1013918.html; reference:url,doc.emergingthreats.net/2001928; classtype:web-application-attack; sid:2001928; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001928
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS XSS Possible Arbitrary Scripting Code Attack in phpBB (private message)"; flow: established,from_server; content:"privmsg.php"; pcre:"/\<a href="[^"]*(script|about|applet|activex|chrome)\s*\:/i"; reference:url,www.securitytracker.com/alerts/2005/May/1013918.html; reference:url,doc.emergingthreats.net/2001928; classtype:web-application-attack; sid:2001928; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **XSS Possible Arbitrary Scripting Code Attack in phpBB (private message)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.securitytracker.com/alerts/2005/May/1013918.html|url,doc.emergingthreats.net/2001928

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS XSS Possible Arbitrary Scripting Code Attack in phpBB (signature)"; flow: established,from_server; content:"_________________"; pcre:"/\<br \/\>_________________\<br \/\>\<a href="[^"]*(script|about|applet|activex|chrome)\s*\:/i"; reference:url,www.securitytracker.com/alerts/2005/May/1013918.html; reference:url,doc.emergingthreats.net/2001929; classtype:web-application-attack; sid:2001929; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2001929
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS XSS Possible Arbitrary Scripting Code Attack in phpBB (signature)"; flow: established,from_server; content:"_________________"; pcre:"/\<br \/\>_________________\<br \/\>\<a href="[^"]*(script|about|applet|activex|chrome)\s*\:/i"; reference:url,www.securitytracker.com/alerts/2005/May/1013918.html; reference:url,doc.emergingthreats.net/2001929; classtype:web-application-attack; sid:2001929; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **XSS Possible Arbitrary Scripting Code Attack in phpBB (signature)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.securitytracker.com/alerts/2005/May/1013918.html|url,doc.emergingthreats.net/2001929

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 7

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB Remote Code Execution Attempt"; flow:established,to_server; uricontent:"/viewtopic.php?"; pcre:"/highlight=.*?(\'|\%[a-f0-9]{4})(\.|\/|\\|\%[a-f0-9]{4}).+?(\'|\%[a-f0-9]{4})/Ui"; reference:url,secunia.com/advisories/15845/; reference:bugtraq,14086; reference:url,www.securiteam.com/unixfocus/6Z00R2ABPY.html; reference:url,doc.emergingthreats.net/2002070; classtype:web-application-attack; sid:2002070; rev:8; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002070
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB Remote Code Execution Attempt"; flow:established,to_server; uricontent:"/viewtopic.php?"; pcre:"/highlight=.*?(\'|\%[a-f0-9]{4})(\.|\/|\\|\%[a-f0-9]{4}).+?(\'|\%[a-f0-9]{4})/Ui"; reference:url,secunia.com/advisories/15845/; reference:bugtraq,14086; reference:url,www.securiteam.com/unixfocus/6Z00R2ABPY.html; reference:url,doc.emergingthreats.net/2002070; classtype:web-application-attack; sid:2002070; rev:8; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpBB Remote Code Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,secunia.com/advisories/15845/|bugtraq,14086|url,www.securiteam.com/unixfocus/6Z00R2ABPY.html|url,doc.emergingthreats.net/2002070

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 8

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Generic phpbb arbitrary command attempt"; flow:established,to_server; uricontent:".php?"; nocase; uricontent:"phpbb_root_path="; nocase; pcre:"/phpbb_root_path=(ftps?|https?|php)/Ui"; reference:url,cve.mitre.org/cgi-bin/cvekey.cgi?keyword=phpbb_root_path; reference:url,doc.emergingthreats.net/2002731; classtype:web-application-attack; sid:2002731; rev:8; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002731
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Generic phpbb arbitrary command attempt"; flow:established,to_server; uricontent:".php?"; nocase; uricontent:"phpbb_root_path="; nocase; pcre:"/phpbb_root_path=(ftps?|https?|php)/Ui"; reference:url,cve.mitre.org/cgi-bin/cvekey.cgi?keyword=phpbb_root_path; reference:url,doc.emergingthreats.net/2002731; classtype:web-application-attack; sid:2002731; rev:8; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Generic phpbb arbitrary command attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,cve.mitre.org/cgi-bin/cvekey.cgi?keyword=phpbb_root_path|url,doc.emergingthreats.net/2002731

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 8

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 registration (Step1 GET)"; flow:to_server,established; content:"GET "; depth:4; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=register"; flowbits:set,ET.phpBB3_test; flowbits:set,ET.phpBB3_register_stage1; flowbits:noalert; reference:url,doc.emergingthreats.net/2010890; classtype:attempted-user; sid:2010890; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010890
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 registration (Step1 GET)"; flow:to_server,established; content:"GET "; depth:4; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=register"; flowbits:set,ET.phpBB3_test; flowbits:set,ET.phpBB3_register_stage1; flowbits:noalert; reference:url,doc.emergingthreats.net/2010890; classtype:attempted-user; sid:2010890; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpBB3 registration (Step1 GET)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,doc.emergingthreats.net/2010890

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 registration (Step2 POST)"; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=register"; content:"agreed=I+agree+to+these+terms"; content:"change_lang="; content:"creation_time"; content:"form_token"; flowbits:set,ET.phpBB3_test; flowbits:isset,ET.phpBB3_register_stage1; flowbits:set,ET.phpBB3_register_stage2; flowbits:noalert; reference:url,doc.emergingthreats.net/2010891; classtype:attempted-user; sid:2010891; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010891
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 registration (Step2 POST)"; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=register"; content:"agreed=I+agree+to+these+terms"; content:"change_lang="; content:"creation_time"; content:"form_token"; flowbits:set,ET.phpBB3_test; flowbits:isset,ET.phpBB3_register_stage1; flowbits:set,ET.phpBB3_register_stage2; flowbits:noalert; reference:url,doc.emergingthreats.net/2010891; classtype:attempted-user; sid:2010891; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpBB3 registration (Step2 POST)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,doc.emergingthreats.net/2010891

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 registration (Step3 GET)"; flow:to_server,established; content:"GET "; depth:4; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=confirm"; uricontent:"confirm_id="; uricontent:"type="; flowbits:set,ET.phpBB3_test; flowbits:set,ET.phpBB3_register_stage3; flowbits:noalert; reference:url,doc.emergingthreats.net/2010892; classtype:attempted-user; sid:2010892; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010892
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 registration (Step3 GET)"; flow:to_server,established; content:"GET "; depth:4; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=confirm"; uricontent:"confirm_id="; uricontent:"type="; flowbits:set,ET.phpBB3_test; flowbits:set,ET.phpBB3_register_stage3; flowbits:noalert; reference:url,doc.emergingthreats.net/2010892; classtype:attempted-user; sid:2010892; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpBB3 registration (Step3 GET)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,doc.emergingthreats.net/2010892

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 registration (Step4 POST)"; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=register"; content:"username="; content:"email="; content:"email_confirm="; content:"new_password"; content:"password_confirm"; content:"lang="; content:"tz="; content:"confirm_code="; content:"refresh_vc="; content:"confirm_id="; content:"agreed="; content:"change_lang="; content:"confirm_id="; content:"creation_time="; content:"form_token="; flowbits:set,ET.phpBB3_test; flowbits:isset,ET.phpBB3_register_stage3; flowbits:set,ET.phpBB3_register_stage4; flowbits:noalert; reference:url,doc.emergingthreats.net/2010893; classtype:attempted-user; sid:2010893; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010893
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 registration (Step4 POST)"; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=register"; content:"username="; content:"email="; content:"email_confirm="; content:"new_password"; content:"password_confirm"; content:"lang="; content:"tz="; content:"confirm_code="; content:"refresh_vc="; content:"confirm_id="; content:"agreed="; content:"change_lang="; content:"confirm_id="; content:"creation_time="; content:"form_token="; flowbits:set,ET.phpBB3_test; flowbits:isset,ET.phpBB3_register_stage3; flowbits:set,ET.phpBB3_register_stage4; flowbits:noalert; reference:url,doc.emergingthreats.net/2010893; classtype:attempted-user; sid:2010893; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpBB3 registration (Step4 POST)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,doc.emergingthreats.net/2010893

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 Brute-Force reg attempt (Bad pf_XXXXX)"; flowbits:isset,ET.phpBB3_test; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=register"; content:"username="; content:"email="; content:"pf_XXXXX="; pcre:!"/^Y$/R"; flowbits:unset,ET.phpBB3_test; reference:url,doc.emergingthreats.net/2010894; classtype:web-application-attack; sid:2010894; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010894
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 Brute-Force reg attempt (Bad pf_XXXXX)"; flowbits:isset,ET.phpBB3_test; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=register"; content:"username="; content:"email="; content:"pf_XXXXX="; pcre:!"/^Y$/R"; flowbits:unset,ET.phpBB3_test; reference:url,doc.emergingthreats.net/2010894; classtype:web-application-attack; sid:2010894; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpBB3 Brute-Force reg attempt (Bad pf_XXXXX)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010894

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 Brute-Force reg attempt (Bad pf_XXXXX)"; flowbits:isset,ET.phpBB3_test; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=register"; content:"username="; content:"email="; content:"pf_XXXXX="; pcre:!"/^YYY$/R"; flowbits:unset,ET.phpBB3_test; reference:url,doc.emergingthreats.net/2010895; classtype:web-application-attack; sid:2010895; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010895
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 Brute-Force reg attempt (Bad pf_XXXXX)"; flowbits:isset,ET.phpBB3_test; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=register"; content:"username="; content:"email="; content:"pf_XXXXX="; pcre:!"/^YYY$/R"; flowbits:unset,ET.phpBB3_test; reference:url,doc.emergingthreats.net/2010895; classtype:web-application-attack; sid:2010895; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpBB3 Brute-Force reg attempt (Bad pf_XXXXX)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010895

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 registration (Bogus Stage3 GET)"; flow:to_server,established; content:"GET "; depth:4; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=confirm"; uricontent:"id="; pcre:"/(\?|&)id=/Ui"; uricontent:"type="; reference:url,doc.emergingthreats.net/2010898; classtype:web-application-attack; sid:2010898; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010898
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 registration (Bogus Stage3 GET)"; flow:to_server,established; content:"GET "; depth:4; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=confirm"; uricontent:"id="; pcre:"/(\?|&)id=/Ui"; uricontent:"type="; reference:url,doc.emergingthreats.net/2010898; classtype:web-application-attack; sid:2010898; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpBB3 registration (Bogus Stage3 GET)** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010898

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 multiple login attempts"; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=login"; threshold: type threshold, track by_src, count 2, seconds 60; reference:url,doc.emergingthreats.net/2010899; classtype:attempted-user; sid:2010899; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010899
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 multiple login attempts"; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/ucp.php"; nocase; uricontent:"mode=login"; threshold: type threshold, track by_src, count 2, seconds 60; reference:url,doc.emergingthreats.net/2010899; classtype:attempted-user; sid:2010899; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpBB3 multiple login attempts** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-user

URL reference : url,doc.emergingthreats.net/2010899

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 possible spammer posting attempts"; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/posting.php"; nocase; uricontent:"mode=post"; threshold: type threshold, track by_src, count 2, seconds 30; reference:url,doc.emergingthreats.net/2010900; classtype:web-application-attack; sid:2010900; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010900
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpBB3 possible spammer posting attempts"; flow:to_server,established; content:"POST "; depth:5; nocase; uricontent:"/posting.php"; nocase; uricontent:"mode=post"; threshold: type threshold, track by_src, count 2, seconds 30; reference:url,doc.emergingthreats.net/2010900; classtype:web-application-attack; sid:2010900; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpBB3 possible spammer posting attempts** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,doc.emergingthreats.net/2010900

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChain XSS Attempt -- settings.php catid"; flow:established,to_server; uricontent:"/settings.php?"; nocase; uricontent:"catid="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2670; reference:url,www.securityfocus.com/bid/23761; reference:url,doc.emergingthreats.net/2003879; classtype:web-application-attack; sid:2003879; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003879
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChain XSS Attempt -- settings.php catid"; flow:established,to_server; uricontent:"/settings.php?"; nocase; uricontent:"catid="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2670; reference:url,www.securityfocus.com/bid/23761; reference:url,doc.emergingthreats.net/2003879; classtype:web-application-attack; sid:2003879; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPChain XSS Attempt -- settings.php catid** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2670|url,www.securityfocus.com/bid/23761|url,doc.emergingthreats.net/2003879

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChain XSS Attempt -- cat.php catid"; flow:established,to_server; uricontent:"/cat.php?"; nocase; uricontent:"catid="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2670; reference:url,www.securityfocus.com/bid/23761; reference:url,doc.emergingthreats.net/2003880; classtype:web-application-attack; sid:2003880; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003880
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChain XSS Attempt -- cat.php catid"; flow:established,to_server; uricontent:"/cat.php?"; nocase; uricontent:"catid="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2670; reference:url,www.securityfocus.com/bid/23761; reference:url,doc.emergingthreats.net/2003880; classtype:web-application-attack; sid:2003880; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPChain XSS Attempt -- cat.php catid** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2670|url,www.securityfocus.com/bid/23761|url,doc.emergingthreats.net/2003880

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChess Remote Inclusion Attempt -- language.php config"; flow:established,to_server; uricontent:"/includes/language.php?"; nocase; uricontent:"config="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2677; reference:url,www.milw0rm.com/exploits/3837; reference:url,doc.emergingthreats.net/2003742; classtype:web-application-attack; sid:2003742; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003742
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChess Remote Inclusion Attempt -- language.php config"; flow:established,to_server; uricontent:"/includes/language.php?"; nocase; uricontent:"config="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2677; reference:url,www.milw0rm.com/exploits/3837; reference:url,doc.emergingthreats.net/2003742; classtype:web-application-attack; sid:2003742; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPChess Remote Inclusion Attempt -- language.php config** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2677|url,www.milw0rm.com/exploits/3837|url,doc.emergingthreats.net/2003742

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChess Remote Inclusion Attempt -- layout_admin_cfg.php Root_Path"; flow:established,to_server; uricontent:"/layout_admin_cfg.php?"; nocase; uricontent:"Root_Path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2677; reference:url,www.milw0rm.com/exploits/3837; reference:url,doc.emergingthreats.net/2003743; classtype:web-application-attack; sid:2003743; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003743
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChess Remote Inclusion Attempt -- layout_admin_cfg.php Root_Path"; flow:established,to_server; uricontent:"/layout_admin_cfg.php?"; nocase; uricontent:"Root_Path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2677; reference:url,www.milw0rm.com/exploits/3837; reference:url,doc.emergingthreats.net/2003743; classtype:web-application-attack; sid:2003743; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPChess Remote Inclusion Attempt -- layout_admin_cfg.php Root_Path** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2677|url,www.milw0rm.com/exploits/3837|url,doc.emergingthreats.net/2003743

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChess Remote Inclusion Attempt -- layout_cfg.php Root_Path"; flow:established,to_server; uricontent:"/layout_cfg.php?"; nocase; uricontent:"Root_Path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2677; reference:url,www.milw0rm.com/exploits/3837; reference:url,doc.emergingthreats.net/2003744; classtype:web-application-attack; sid:2003744; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003744
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChess Remote Inclusion Attempt -- layout_cfg.php Root_Path"; flow:established,to_server; uricontent:"/layout_cfg.php?"; nocase; uricontent:"Root_Path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2677; reference:url,www.milw0rm.com/exploits/3837; reference:url,doc.emergingthreats.net/2003744; classtype:web-application-attack; sid:2003744; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPChess Remote Inclusion Attempt -- layout_cfg.php Root_Path** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2677|url,www.milw0rm.com/exploits/3837|url,doc.emergingthreats.net/2003744

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChess Remote Inclusion Attempt -- layout_t_top.php Root_Path"; flow:established,to_server; uricontent:"/skins/phpchess/layout_t_top.php?"; nocase; uricontent:"Root_Path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2677; reference:url,www.milw0rm.com/exploits/3837; reference:url,doc.emergingthreats.net/2003745; classtype:web-application-attack; sid:2003745; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003745
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPChess Remote Inclusion Attempt -- layout_t_top.php Root_Path"; flow:established,to_server; uricontent:"/skins/phpchess/layout_t_top.php?"; nocase; uricontent:"Root_Path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2677; reference:url,www.milw0rm.com/exploits/3837; reference:url,doc.emergingthreats.net/2003745; classtype:web-application-attack; sid:2003745; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPChess Remote Inclusion Attempt -- layout_t_top.php Root_Path** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2677|url,www.milw0rm.com/exploits/3837|url,doc.emergingthreats.net/2003745

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPEventMan remote file include"; flow:established,to_server; uricontent:"/controller/"; nocase; pcre:"/(text\.ctrl\.php|common\.function\.php)\?level=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,22358; reference:url,doc.emergingthreats.net/2003372; classtype:web-application-attack; sid:2003372; rev:5; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003372
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPEventMan remote file include"; flow:established,to_server; uricontent:"/controller/"; nocase; pcre:"/(text\.ctrl\.php|common\.function\.php)\?level=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,22358; reference:url,doc.emergingthreats.net/2003372; classtype:web-application-attack; sid:2003372; rev:5; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPEventMan remote file include** 

Attack target : Server

Description : Remote File Include (RFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked into including remote files with malicious code. File inclusion is typically used for packaging common code into separate files that are later referenced by main application modules. When a web application references an include file, the code in this file may be executed implicitly or explicitly by calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the web application might be vulnerable to RFI.

PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch further, more sophisticated attacks should a server respond in a way that reveals it is vulnerable. You may see hundreds of these alerts in a short period of time indicating you are the target of a scanning campaign, all of which may be FPs. If you see a HTTP 200 response in the web server log files for the request generating the alert, you’ll want to investigate to determine if the attack was successful. Typically, after a successful attack, attackers will wget a trojan from a third party site and execute it, so that the attacker maintains control even if the vulnerable software is patched..

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Remote_File_Include

Affected products : Any

Alert Classtype : web-application-attack

URL reference : bugtraq,22358|url,doc.emergingthreats.net/2003372

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPFirstPost Remote Inclusion Attempt block.php Include"; flow:established,to_server; uricontent:"/block.php?"; nocase; uricontent:"Include="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2665; reference:url,www.milw0rm.com/exploits/3906; reference:url,doc.emergingthreats.net/2003740; classtype:web-application-attack; sid:2003740; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003740
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPFirstPost Remote Inclusion Attempt block.php Include"; flow:established,to_server; uricontent:"/block.php?"; nocase; uricontent:"Include="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2665; reference:url,www.milw0rm.com/exploits/3906; reference:url,doc.emergingthreats.net/2003740; classtype:web-application-attack; sid:2003740; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPFirstPost Remote Inclusion Attempt block.php Include** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2665|url,www.milw0rm.com/exploits/3906|url,doc.emergingthreats.net/2003740

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPGenealogy CoupleDB.php DataDirectory Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/CoupleDB.php?"; nocase; uricontent:"DataDirectory="; nocase; pcre:"/DataDirectory=\s*(ftps?|https?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/9155; reference:url,packetstormsecurity.org/0907-exploits/phpgenealogy-rfi.txt; reference:url,doc.emergingthreats.net/2010095; classtype:web-application-attack; sid:2010095; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010095
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPGenealogy CoupleDB.php DataDirectory Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/CoupleDB.php?"; nocase; uricontent:"DataDirectory="; nocase; pcre:"/DataDirectory=\s*(ftps?|https?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/9155; reference:url,packetstormsecurity.org/0907-exploits/phpgenealogy-rfi.txt; reference:url,doc.emergingthreats.net/2010095; classtype:web-application-attack; sid:2010095; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPGenealogy CoupleDB.php DataDirectory Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/9155|url,packetstormsecurity.org/0907-exploits/phpgenealogy-rfi.txt|url,doc.emergingthreats.net/2010095

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER SELECT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"SELECT"; nocase; uricontent:"FROM"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003805; classtype:web-application-attack; sid:2003805; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003805
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER SELECT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"SELECT"; nocase; uricontent:"FROM"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003805; classtype:web-application-attack; sid:2003805; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER SELECT** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003805

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER UNION SELECT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003806; classtype:web-application-attack; sid:2003806; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003806
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER UNION SELECT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003806; classtype:web-application-attack; sid:2003806; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER UNION SELECT** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003806

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER INSERT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003807; classtype:web-application-attack; sid:2003807; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003807
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER INSERT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003807; classtype:web-application-attack; sid:2003807; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER INSERT** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003807

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER DELETE"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003808; classtype:web-application-attack; sid:2003808; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003808
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER DELETE"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003808; classtype:web-application-attack; sid:2003808; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER DELETE** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003808

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER ASCII"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003809; classtype:web-application-attack; sid:2003809; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003809
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER ASCII"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003809; classtype:web-application-attack; sid:2003809; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER ASCII** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003809

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER UPDATE"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003810; classtype:web-application-attack; sid:2003810; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003810
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER UPDATE"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_USER="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003810; classtype:web-application-attack; sid:2003810; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_USER UPDATE** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003810

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS SELECT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"SELECT"; nocase; uricontent:"FROM"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003811; classtype:web-application-attack; sid:2003811; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003811
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS SELECT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"SELECT"; nocase; uricontent:"FROM"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003811; classtype:web-application-attack; sid:2003811; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS SELECT** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003811

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS UNION SELECT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003812; classtype:web-application-attack; sid:2003812; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003812
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS UNION SELECT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003812; classtype:web-application-attack; sid:2003812; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS UNION SELECT** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003812

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS INSERT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003813; classtype:web-application-attack; sid:2003813; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003813
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS INSERT"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003813; classtype:web-application-attack; sid:2003813; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS INSERT** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003813

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS DELETE"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003814; classtype:web-application-attack; sid:2003814; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003814
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS DELETE"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003814; classtype:web-application-attack; sid:2003814; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS DELETE** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003814

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS ASCII"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003815; classtype:web-application-attack; sid:2003815; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003815
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS ASCII"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003815; classtype:web-application-attack; sid:2003815; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS ASCII** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003815

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS UPDATE"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003816; classtype:web-application-attack; sid:2003816; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003816
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS UPDATE"; flow:established,to_server; uricontent:"/admin.php?"; nocase; uricontent:"ADMIN_PASS="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2534; reference:url,www.securityfocus.com/bid/23854; reference:url,doc.emergingthreats.net/2003816; classtype:web-application-attack; sid:2003816; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpHoo3 SQL Injection Attempt -- admin.php ADMIN_PASS UPDATE** 

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

URL reference : cve,CVE-2007-2534|url,www.securityfocus.com/bid/23854|url,doc.emergingthreats.net/2003816

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPHtmlLib Remote Inclusion Attempt -- widget8.php phphtmllib"; flow:established,to_server; uricontent:"/examples/widget8.php?"; nocase; uricontent:"phphtmllib="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2614; reference:url,www.securityfocus.com/archive/1/archive/1/467837/100/0/threaded; reference:url,doc.emergingthreats.net/2003730; classtype:web-application-attack; sid:2003730; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003730
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPHtmlLib Remote Inclusion Attempt -- widget8.php phphtmllib"; flow:established,to_server; uricontent:"/examples/widget8.php?"; nocase; uricontent:"phphtmllib="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2614; reference:url,www.securityfocus.com/archive/1/archive/1/467837/100/0/threaded; reference:url,doc.emergingthreats.net/2003730; classtype:web-application-attack; sid:2003730; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPHtmlLib Remote Inclusion Attempt -- widget8.php phphtmllib** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2614|url,www.securityfocus.com/archive/1/archive/1/467837/100/0/threaded|url,doc.emergingthreats.net/2003730

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPLojaFacil Remote Inclusion Attempt -- ftp.php path_local"; flow:established,to_server; uricontent:"/ftp.php?"; nocase; uricontent:"path_local="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2615; reference:url,www.milw0rm.com/exploits/3875; reference:url,doc.emergingthreats.net/2003731; classtype:web-application-attack; sid:2003731; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003731
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPLojaFacil Remote Inclusion Attempt -- ftp.php path_local"; flow:established,to_server; uricontent:"/ftp.php?"; nocase; uricontent:"path_local="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2615; reference:url,www.milw0rm.com/exploits/3875; reference:url,doc.emergingthreats.net/2003731; classtype:web-application-attack; sid:2003731; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPLojaFacil Remote Inclusion Attempt -- ftp.php path_local** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2615|url,www.milw0rm.com/exploits/3875|url,doc.emergingthreats.net/2003731

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPLojaFacil Remote Inclusion Attempt -- db.php path_local"; flow:established,to_server; uricontent:"/libs/db.php?"; nocase; uricontent:"path_local="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2615; reference:url,www.milw0rm.com/exploits/3875; reference:url,doc.emergingthreats.net/2003732; classtype:web-application-attack; sid:2003732; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003732
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPLojaFacil Remote Inclusion Attempt -- db.php path_local"; flow:established,to_server; uricontent:"/libs/db.php?"; nocase; uricontent:"path_local="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2615; reference:url,www.milw0rm.com/exploits/3875; reference:url,doc.emergingthreats.net/2003732; classtype:web-application-attack; sid:2003732; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPLojaFacil Remote Inclusion Attempt -- db.php path_local** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2615|url,www.milw0rm.com/exploits/3875|url,doc.emergingthreats.net/2003732

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPLojaFacil Remote Inclusion Attempt -- libs_ftp.php path_local"; flow:established,to_server; uricontent:"/libs/ftp.php?"; nocase; uricontent:"path_local="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2615; reference:url,www.milw0rm.com/exploits/3875; reference:url,doc.emergingthreats.net/2003733; classtype:web-application-attack; sid:2003733; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003733
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPLojaFacil Remote Inclusion Attempt -- libs_ftp.php path_local"; flow:established,to_server; uricontent:"/libs/ftp.php?"; nocase; uricontent:"path_local="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2615; reference:url,www.milw0rm.com/exploits/3875; reference:url,doc.emergingthreats.net/2003733; classtype:web-application-attack; sid:2003733; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPLojaFacil Remote Inclusion Attempt -- libs_ftp.php path_local** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2615|url,www.milw0rm.com/exploits/3875|url,doc.emergingthreats.net/2003733

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPmyGallery confdir parameter Remote File Inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/_conf/core/common-tpl-vars.php?"; nocase; uricontent:"confdir="; nocase; pcre:"/confdir=\s*(ftps?|https?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/7392; reference:bugtraq,32705; reference:url,doc.emergingthreats.net/2008962; classtype:web-application-attack; sid:2008962; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2008962
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPmyGallery confdir parameter Remote File Inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/_conf/core/common-tpl-vars.php?"; nocase; uricontent:"confdir="; nocase; pcre:"/confdir=\s*(ftps?|https?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/7392; reference:bugtraq,32705; reference:url,doc.emergingthreats.net/2008962; classtype:web-application-attack; sid:2008962; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPmyGallery confdir parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/7392|bugtraq,32705|url,doc.emergingthreats.net/2008962

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPOutsourcing Zorum prod.php Remote Command Execution Attempt"; flow:to_server,established; uricontent:"/prod.php?"; nocase; pcre:"/(argv[1]=\|.+)/"; reference:bugtraq,14601; reference:url,doc.emergingthreats.net/2002314; classtype:web-application-attack; sid:2002314; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002314
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPOutsourcing Zorum prod.php Remote Command Execution Attempt"; flow:to_server,established; uricontent:"/prod.php?"; nocase; pcre:"/(argv[1]=\|.+)/"; reference:bugtraq,14601; reference:url,doc.emergingthreats.net/2002314; classtype:web-application-attack; sid:2002314; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPOutsourcing Zorum prod.php Remote Command Execution Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,14601|url,doc.emergingthreats.net/2002314

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 7

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPSecurityAdmin Remote Inclusion Attempt -- logout.php PSA_PATH"; flow:established,to_server; uricontent:"/include/logout.php?"; nocase; uricontent:"PSA_PATH="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2628; reference:url,www.securityfocus.com/bid/23801; reference:url,doc.emergingthreats.net/2003735; classtype:web-application-attack; sid:2003735; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003735
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPSecurityAdmin Remote Inclusion Attempt -- logout.php PSA_PATH"; flow:established,to_server; uricontent:"/include/logout.php?"; nocase; uricontent:"PSA_PATH="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2628; reference:url,www.securityfocus.com/bid/23801; reference:url,doc.emergingthreats.net/2003735; classtype:web-application-attack; sid:2003735; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPSecurityAdmin Remote Inclusion Attempt -- logout.php PSA_PATH** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2628|url,www.securityfocus.com/bid/23801|url,doc.emergingthreats.net/2003735

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPStore Yahoo Answers id parameter SQL Injection"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/index.php?"; nocase; uricontent:"cmd=4"; nocase; uricontent:"id="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/UNION.+SELECT/Ui"; reference:url,secunia.com/advisories/32717/; reference:url,milw0rm.com/exploits/7131; reference:url,doc.emergingthreats.net/2008874; classtype:web-application-attack; sid:2008874; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2008874
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPStore Yahoo Answers id parameter SQL Injection"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/index.php?"; nocase; uricontent:"cmd=4"; nocase; uricontent:"id="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/UNION.+SELECT/Ui"; reference:url,secunia.com/advisories/32717/; reference:url,milw0rm.com/exploits/7131; reference:url,doc.emergingthreats.net/2008874; classtype:web-application-attack; sid:2008874; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPStore Yahoo Answers id parameter SQL Injection** 

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

URL reference : url,secunia.com/advisories/32717/|url,milw0rm.com/exploits/7131|url,doc.emergingthreats.net/2008874

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPNuke general XSS attempt"; flow: to_server,established; uricontent:"/modules.php?"; uricontent:"name="; uricontent:"SCRIPT"; nocase; pcre:"/<\s*SCRIPT\s*>/iU"; reference:url,www.waraxe.us/?modname=sa&id=030; reference:url,doc.emergingthreats.net/2001218; classtype:web-application-attack; sid:2001218; rev:11; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2001218
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPNuke general XSS attempt"; flow: to_server,established; uricontent:"/modules.php?"; uricontent:"name="; uricontent:"SCRIPT"; nocase; pcre:"/<\s*SCRIPT\s*>/iU"; reference:url,www.waraxe.us/?modname=sa&id=030; reference:url,doc.emergingthreats.net/2001218; classtype:web-application-attack; sid:2001218; rev:11; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPNuke general XSS attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.waraxe.us/?modname=sa&id=030|url,doc.emergingthreats.net/2001218

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 11

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHP PHPNuke Remote File Inclusion Attempt"; flow:established,to_server; uricontent:"/iframe.php"; nocase; uricontent:"file="; nocase; pcre:"/file=\s*(ftps?|https?|php)\:\//Ui"; reference:url,www.zone-h.org/en/advisories/read/id=8694/; reference:url,doc.emergingthreats.net/2002800; classtype:web-application-attack; sid:2002800; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002800
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHP PHPNuke Remote File Inclusion Attempt"; flow:established,to_server; uricontent:"/iframe.php"; nocase; uricontent:"file="; nocase; pcre:"/file=\s*(ftps?|https?|php)\:\//Ui"; reference:url,www.zone-h.org/en/advisories/read/id=8694/; reference:url,doc.emergingthreats.net/2002800; classtype:web-application-attack; sid:2002800; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHP PHPNuke Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.zone-h.org/en/advisories/read/id=8694/|url,doc.emergingthreats.net/2002800

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHP Web Calendar Remote File Inclusion Attempt"; flow:established,to_server; uricontent:"/send_reminders.php"; nocase; pcre:"/includedir=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,14651; reference:cve,2005-2717; reference:url,doc.emergingthreats.net/2002898; classtype:web-application-attack; sid:2002898; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002898
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHP Web Calendar Remote File Inclusion Attempt"; flow:established,to_server; uricontent:"/send_reminders.php"; nocase; pcre:"/includedir=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,14651; reference:cve,2005-2717; reference:url,doc.emergingthreats.net/2002898; classtype:web-application-attack; sid:2002898; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHP Web Calendar Remote File Inclusion Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,14651|cve,2005-2717|url,doc.emergingthreats.net/2002898

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 7

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPtree Remote Inclusion Attempt -- cms2.php s_dir"; flow:established,to_server; uricontent:"/plugin/HP_DEV/cms2.php?"; nocase; uricontent:"s_dir="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2573; reference:url,www.milw0rm.com/exploits/3860; reference:url,doc.emergingthreats.net/2003693; classtype:web-application-attack; sid:2003693; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003693
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHPtree Remote Inclusion Attempt -- cms2.php s_dir"; flow:established,to_server; uricontent:"/plugin/HP_DEV/cms2.php?"; nocase; uricontent:"s_dir="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2573; reference:url,www.milw0rm.com/exploits/3860; reference:url,doc.emergingthreats.net/2003693; classtype:web-application-attack; sid:2003693; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHPtree Remote Inclusion Attempt -- cms2.php s_dir** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2573|url,www.milw0rm.com/exploits/3860|url,doc.emergingthreats.net/2003693

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PmWiki Globals Variables Overwrite Attempt"; flow:to_server,established; uricontent:"/pmwiki.php"; nocase; content:"GLOBALS[FarmD]="; nocase; pcre:"/GLOBALS\x5bFarmD\x5d\x3d/i"; reference:cve,CVE-2006-0479; reference:bugtraq,16421; reference:nessus,20891; reference:url,doc.emergingthreats.net/2002837; classtype:web-application-attack; sid:2002837; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002837
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PmWiki Globals Variables Overwrite Attempt"; flow:to_server,established; uricontent:"/pmwiki.php"; nocase; content:"GLOBALS[FarmD]="; nocase; pcre:"/GLOBALS\x5bFarmD\x5d\x3d/i"; reference:cve,CVE-2006-0479; reference:bugtraq,16421; reference:nessus,20891; reference:url,doc.emergingthreats.net/2002837; classtype:web-application-attack; sid:2002837; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PmWiki Globals Variables Overwrite Attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2006-0479|bugtraq,16421|nessus,20891|url,doc.emergingthreats.net/2002837

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004606; classtype:web-application-attack; sid:2004606; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004606
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004606; classtype:web-application-attack; sid:2004606; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PNphpBB2 SQL Injection Attempt -- index.php c SELECT** 

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

URL reference : cve,CVE-2007-3052|url,www.milw0rm.com/exploits/4026|url,doc.emergingthreats.net/2004606

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004607; classtype:web-application-attack; sid:2004607; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004607
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004607; classtype:web-application-attack; sid:2004607; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PNphpBB2 SQL Injection Attempt -- index.php c UNION SELECT** 

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

URL reference : cve,CVE-2007-3052|url,www.milw0rm.com/exploits/4026|url,doc.emergingthreats.net/2004607

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004608; classtype:web-application-attack; sid:2004608; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004608
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004608; classtype:web-application-attack; sid:2004608; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PNphpBB2 SQL Injection Attempt -- index.php c INSERT** 

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

URL reference : cve,CVE-2007-3052|url,www.milw0rm.com/exploits/4026|url,doc.emergingthreats.net/2004608

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004609; classtype:web-application-attack; sid:2004609; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004609
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004609; classtype:web-application-attack; sid:2004609; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PNphpBB2 SQL Injection Attempt -- index.php c DELETE** 

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

URL reference : cve,CVE-2007-3052|url,www.milw0rm.com/exploits/4026|url,doc.emergingthreats.net/2004609

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004610; classtype:web-application-attack; sid:2004610; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004610
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004610; classtype:web-application-attack; sid:2004610; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PNphpBB2 SQL Injection Attempt -- index.php c ASCII** 

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

URL reference : cve,CVE-2007-3052|url,www.milw0rm.com/exploits/4026|url,doc.emergingthreats.net/2004610

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004611; classtype:web-application-attack; sid:2004611; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004611
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PNphpBB2 SQL Injection Attempt -- index.php c UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"c="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-3052; reference:url,www.milw0rm.com/exploits/4026; reference:url,doc.emergingthreats.net/2004611; classtype:web-application-attack; sid:2004611; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PNphpBB2 SQL Injection Attempt -- index.php c UPDATE** 

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

URL reference : cve,CVE-2007-3052|url,www.milw0rm.com/exploits/4026|url,doc.emergingthreats.net/2004611

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Particle Gallery XSS Attempt -- search.php order"; flow:established,to_server; uricontent:"/search.php?"; nocase; uricontent:"order="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-2962; reference:url,www.securityfocus.com/archive/1/archive/1/469985/100/0/threaded; reference:url,doc.emergingthreats.net/2004582; classtype:web-application-attack; sid:2004582; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004582
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Particle Gallery XSS Attempt -- search.php order"; flow:established,to_server; uricontent:"/search.php?"; nocase; uricontent:"order="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-2962; reference:url,www.securityfocus.com/archive/1/archive/1/469985/100/0/threaded; reference:url,doc.emergingthreats.net/2004582; classtype:web-application-attack; sid:2004582; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Particle Gallery XSS Attempt -- search.php order** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2962|url,www.securityfocus.com/archive/1/archive/1/469985/100/0/threaded|url,doc.emergingthreats.net/2004582

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt - Headerfile.php System"; flow:established,to_server; uricontent:"/blocks/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003660; classtype:web-application-attack; sid:2003660; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003660
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt - Headerfile.php System"; flow:established,to_server; uricontent:"/blocks/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003660; classtype:web-application-attack; sid:2003660; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Persism CMS Remote Inclusion Attempt - Headerfile.php System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2545|url,www.milw0rm.com/exploits/3853|url,doc.emergingthreats.net/2003660

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- latest_files.php System"; flow:established,to_server; uricontent:"/files/blocks/latest_files.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003661; classtype:web-application-attack; sid:2003661; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003661
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- latest_files.php System"; flow:established,to_server; uricontent:"/files/blocks/latest_files.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003661; classtype:web-application-attack; sid:2003661; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Persism CMS Remote Inclusion Attempt -- latest_files.php System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2545|url,www.milw0rm.com/exploits/3853|url,doc.emergingthreats.net/2003661

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- latest_posts.php System"; flow:established,to_server; uricontent:"/forums/blocks/latest_posts.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003662; classtype:web-application-attack; sid:2003662; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003662
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- latest_posts.php System"; flow:established,to_server; uricontent:"/forums/blocks/latest_posts.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003662; classtype:web-application-attack; sid:2003662; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Persism CMS Remote Inclusion Attempt -- latest_posts.php System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2545|url,www.milw0rm.com/exploits/3853|url,doc.emergingthreats.net/2003662

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- groups_headerfile.php System"; flow:established,to_server; uricontent:"/groups/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003663; classtype:web-application-attack; sid:2003663; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003663
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- groups_headerfile.php System"; flow:established,to_server; uricontent:"/groups/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003663; classtype:web-application-attack; sid:2003663; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Persism CMS Remote Inclusion Attempt -- groups_headerfile.php System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2545|url,www.milw0rm.com/exploits/3853|url,doc.emergingthreats.net/2003663

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- filters_headerfile.php System"; flow:established,to_server; uricontent:"/filters/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003664; classtype:web-application-attack; sid:2003664; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003664
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- filters_headerfile.php System"; flow:established,to_server; uricontent:"/filters/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003664; classtype:web-application-attack; sid:2003664; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Persism CMS Remote Inclusion Attempt -- filters_headerfile.php System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2545|url,www.milw0rm.com/exploits/3853|url,doc.emergingthreats.net/2003664

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- links.php System"; flow:established,to_server; uricontent:"/links/blocks/links.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003665; classtype:web-application-attack; sid:2003665; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003665
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- links.php System"; flow:established,to_server; uricontent:"/links/blocks/links.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003665; classtype:web-application-attack; sid:2003665; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Persism CMS Remote Inclusion Attempt -- links.php System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2545|url,www.milw0rm.com/exploits/3853|url,doc.emergingthreats.net/2003665

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- menu_headerfile.php System"; flow:established,to_server; uricontent:"/menu/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003666; classtype:web-application-attack; sid:2003666; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003666
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- menu_headerfile.php System"; flow:established,to_server; uricontent:"/menu/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003666; classtype:web-application-attack; sid:2003666; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Persism CMS Remote Inclusion Attempt -- menu_headerfile.php System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2545|url,www.milw0rm.com/exploits/3853|url,doc.emergingthreats.net/2003666

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- latest_news.php System"; flow:established,to_server; uricontent:"/news/blocks/latest_news.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003667; classtype:web-application-attack; sid:2003667; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003667
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- latest_news.php System"; flow:established,to_server; uricontent:"/news/blocks/latest_news.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003667; classtype:web-application-attack; sid:2003667; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Persism CMS Remote Inclusion Attempt -- latest_news.php System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2545|url,www.milw0rm.com/exploits/3853|url,doc.emergingthreats.net/2003667

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- settings_headerfile.php System"; flow:established,to_server; uricontent:"/settings/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003668; classtype:web-application-attack; sid:2003668; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003668
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- settings_headerfile.php System"; flow:established,to_server; uricontent:"/settings/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003668; classtype:web-application-attack; sid:2003668; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Persism CMS Remote Inclusion Attempt -- settings_headerfile.php System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2545|url,www.milw0rm.com/exploits/3853|url,doc.emergingthreats.net/2003668

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- users_headerfile.php System"; flow:established,to_server; uricontent:"/modules/users/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003681; classtype:web-application-attack; sid:2003681; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003681
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Persism CMS Remote Inclusion Attempt -- users_headerfile.php System"; flow:established,to_server; uricontent:"/modules/users/headerfile.php?"; nocase; uricontent:"system["; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2545; reference:url,www.milw0rm.com/exploits/3853; reference:url,doc.emergingthreats.net/2003681; classtype:web-application-attack; sid:2003681; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Persism CMS Remote Inclusion Attempt -- users_headerfile.php System** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2545|url,www.milw0rm.com/exploits/3853|url,doc.emergingthreats.net/2003681

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004089; classtype:web-application-attack; sid:2004089; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004089
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004089; classtype:web-application-attack; sid:2004089; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Phil-a-Form SQL Injection Attempt -- index.php form_id SELECT** 

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

URL reference : cve,CVE-2007-2933|url,www.milw0rm.com/exploits/4003|url,doc.emergingthreats.net/2004089

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004090; classtype:web-application-attack; sid:2004090; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004090
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004090; classtype:web-application-attack; sid:2004090; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Phil-a-Form SQL Injection Attempt -- index.php form_id UNION SELECT** 

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

URL reference : cve,CVE-2007-2933|url,www.milw0rm.com/exploits/4003|url,doc.emergingthreats.net/2004090

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004091; classtype:web-application-attack; sid:2004091; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004091
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004091; classtype:web-application-attack; sid:2004091; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Phil-a-Form SQL Injection Attempt -- index.php form_id INSERT** 

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

URL reference : cve,CVE-2007-2933|url,www.milw0rm.com/exploits/4003|url,doc.emergingthreats.net/2004091

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004092; classtype:web-application-attack; sid:2004092; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004092
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004092; classtype:web-application-attack; sid:2004092; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Phil-a-Form SQL Injection Attempt -- index.php form_id DELETE** 

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

URL reference : cve,CVE-2007-2933|url,www.milw0rm.com/exploits/4003|url,doc.emergingthreats.net/2004092

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004093; classtype:web-application-attack; sid:2004093; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004093
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004093; classtype:web-application-attack; sid:2004093; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Phil-a-Form SQL Injection Attempt -- index.php form_id ASCII** 

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

URL reference : cve,CVE-2007-2933|url,www.milw0rm.com/exploits/4003|url,doc.emergingthreats.net/2004093

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"UPDATE"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004094; classtype:web-application-attack; sid:2004094; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004094
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Phil-a-Form SQL Injection Attempt -- index.php form_id UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"form_id="; nocase; uricontent:"UPDATE"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2933; reference:url,www.milw0rm.com/exploits/4003; reference:url,doc.emergingthreats.net/2004094; classtype:web-application-attack; sid:2004094; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Phil-a-Form SQL Injection Attempt -- index.php form_id UPDATE** 

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

URL reference : cve,CVE-2007-2933|url,www.milw0rm.com/exploits/4003|url,doc.emergingthreats.net/2004094

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PhpBlock basicfogfactory.class.php PATH_TO_CODE Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/basicfogfactory.class.php?"; nocase; uricontent:"PATH_TO_CODE="; nocase; pcre:"/PATH_TO_CODE=\s*(https?|ftps?|php)\:\//Ui"; reference:bugtraq,28588; reference:url,milw0rm.com/exploits/5348; reference:url,doc.emergingthreats.net/2009415; classtype:web-application-attack; sid:2009415; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009415
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PhpBlock basicfogfactory.class.php PATH_TO_CODE Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/basicfogfactory.class.php?"; nocase; uricontent:"PATH_TO_CODE="; nocase; pcre:"/PATH_TO_CODE=\s*(https?|ftps?|php)\:\//Ui"; reference:bugtraq,28588; reference:url,milw0rm.com/exploits/5348; reference:url,doc.emergingthreats.net/2009415; classtype:web-application-attack; sid:2009415; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PhpBlock basicfogfactory.class.php PATH_TO_CODE Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,28588|url,milw0rm.com/exploits/5348|url,doc.emergingthreats.net/2009415

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpFan init.php Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/init.php?"; nocase; uricontent:"includepath="; nocase; pcre:"/includepath=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32335; reference:url,milw0rm.com/exploits/7143; reference:url,doc.emergingthreats.net/2008871; classtype:web-application-attack; sid:2008871; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2008871
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS phpFan init.php Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/init.php?"; nocase; uricontent:"includepath="; nocase; pcre:"/includepath=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32335; reference:url,milw0rm.com/exploits/7143; reference:url,doc.emergingthreats.net/2008871; classtype:web-application-attack; sid:2008871; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **phpFan init.php Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32335|url,milw0rm.com/exploits/7143|url,doc.emergingthreats.net/2008871

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Pie RSS module lib parameter remote file inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/lib/action/rss.php?"; nocase; uricontent:"lib="; nocase; pcre:"/lib=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32465; reference:url,milw0rm.com/exploits/7225; reference:url,doc.emergingthreats.net/2008899; classtype:web-application-attack; sid:2008899; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2008899
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Pie RSS module lib parameter remote file inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/lib/action/rss.php?"; nocase; uricontent:"lib="; nocase; pcre:"/lib=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32465; reference:url,milw0rm.com/exploits/7225; reference:url,doc.emergingthreats.net/2008899; classtype:web-application-attack; sid:2008899; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Pie RSS module lib parameter remote file inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32465|url,milw0rm.com/exploits/7225|url,doc.emergingthreats.net/2008899

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Piranha default passwd attempt"; flow:to_server,established; uricontent:"/piranha/secure/control.php3"; content:"Authorization\: Basic cGlyYW5oYTp"; reference:bugtraq,1148; reference:cve,2000-0248; reference:nessus,10381; reference:url,doc.emergingthreats.net/2002331; classtype:attempted-recon; sid:2002331; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002331
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Piranha default passwd attempt"; flow:to_server,established; uricontent:"/piranha/secure/control.php3"; content:"Authorization\: Basic cGlyYW5oYTp"; reference:bugtraq,1148; reference:cve,2000-0248; reference:nessus,10381; reference:url,doc.emergingthreats.net/2002331; classtype:attempted-recon; sid:2002331; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Piranha default passwd attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : bugtraq,1148|cve,2000-0248|nessus,10381|url,doc.emergingthreats.net/2002331

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Plume CMS prepend.php Remote File Inclusion attempt"; flow:to_server,established; uricontent:"/prepend.php"; nocase; content:"_px_config[manager_path]="; nocase; pcre:"/_px_config\x5bmanager_path\x5d=(https?|ftps?|php)\:/i"; reference:cve,CVE-2006-0725; reference:bugtraq,16662; reference:nessus,20972; reference:url,doc.emergingthreats.net/2002815; classtype:web-application-attack; sid:2002815; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002815
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Plume CMS prepend.php Remote File Inclusion attempt"; flow:to_server,established; uricontent:"/prepend.php"; nocase; content:"_px_config[manager_path]="; nocase; pcre:"/_px_config\x5bmanager_path\x5d=(https?|ftps?|php)\:/i"; reference:cve,CVE-2006-0725; reference:bugtraq,16662; reference:nessus,20972; reference:url,doc.emergingthreats.net/2002815; classtype:web-application-attack; sid:2002815; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Plume CMS prepend.php Remote File Inclusion attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2006-0725|bugtraq,16662|nessus,20972|url,doc.emergingthreats.net/2002815

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 7

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Podium CMS XSS Attempt -- Default.aspx id"; flow:established,to_server; uricontent:"/Default.aspx?"; nocase; uricontent:"id="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2555; reference:url,www.securityfocus.com/archive/1/archive/1/467823/100/0/threaded; reference:url,doc.emergingthreats.net/2003914; classtype:web-application-attack; sid:2003914; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003914
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Podium CMS XSS Attempt -- Default.aspx id"; flow:established,to_server; uricontent:"/Default.aspx?"; nocase; uricontent:"id="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2555; reference:url,www.securityfocus.com/archive/1/archive/1/467823/100/0/threaded; reference:url,doc.emergingthreats.net/2003914; classtype:web-application-attack; sid:2003914; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Podium CMS XSS Attempt -- Default.aspx id** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2555|url,www.securityfocus.com/archive/1/archive/1/467823/100/0/threaded|url,doc.emergingthreats.net/2003914

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Pragyan CMS form.lib.php sourceFolder Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/cms/modules/form.lib.php?"; nocase; uricontent:"sourceFolder="; nocase; pcre:"/sourceFolder=\s*(ftps?|https?|php)\://Ui"; reference:bugtraq,30235; reference:url,juniper.net/security/auto/vulnerabilities/vuln30235.html; reference:url,milw0rm.com/exploits/6078; reference:url,doc.emergingthreats.net/2009898; classtype:web-application-attack; sid:2009898; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009898
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Pragyan CMS form.lib.php sourceFolder Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/cms/modules/form.lib.php?"; nocase; uricontent:"sourceFolder="; nocase; pcre:"/sourceFolder=\s*(ftps?|https?|php)\://Ui"; reference:bugtraq,30235; reference:url,juniper.net/security/auto/vulnerabilities/vuln30235.html; reference:url,milw0rm.com/exploits/6078; reference:url,doc.emergingthreats.net/2009898; classtype:web-application-attack; sid:2009898; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Pragyan CMS form.lib.php sourceFolder Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,30235|url,juniper.net/security/auto/vulnerabilities/vuln30235.html|url,milw0rm.com/exploits/6078|url,doc.emergingthreats.net/2009898

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ProjectCMS select_image.php dir Parameter Directory Traversal"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/imagelibrary/select_image.php?"; nocase; uricontent:"dir="; nocase; content:"../"; reference:url,milw0rm.com/exploits/8608; reference:bugtraq,34816; reference:url,doc.emergingthreats.net/2009736; classtype:web-application-attack; sid:2009736; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009736
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ProjectCMS select_image.php dir Parameter Directory Traversal"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/imagelibrary/select_image.php?"; nocase; uricontent:"dir="; nocase; content:"../"; reference:url,milw0rm.com/exploits/8608; reference:bugtraq,34816; reference:url,doc.emergingthreats.net/2009736; classtype:web-application-attack; sid:2009736; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ProjectCMS select_image.php dir Parameter Directory Traversal** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/8608|bugtraq,34816|url,doc.emergingthreats.net/2009736

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ProjectCMS admin_theme_remove.php file Parameter Remote Directory Delete"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/admin_includes/admin_theme_remove.php?"; nocase; uricontent:"file="; nocase; content:"../"; reference:url,milw0rm.com/exploits/8608; reference:bugtraq,34816; reference:url,doc.emergingthreats.net/2009737; classtype:web-application-attack; sid:2009737; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009737
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ProjectCMS admin_theme_remove.php file Parameter Remote Directory Delete"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/admin_includes/admin_theme_remove.php?"; nocase; uricontent:"file="; nocase; content:"../"; reference:url,milw0rm.com/exploits/8608; reference:bugtraq,34816; reference:url,doc.emergingthreats.net/2009737; classtype:web-application-attack; sid:2009737; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ProjectCMS admin_theme_remove.php file Parameter Remote Directory Delete** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/8608|bugtraq,34816|url,doc.emergingthreats.net/2009737

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PsychoStats XSS Attempt -- awards.php"; flow:established,to_server; uricontent:"/awards.php?"; nocase; uricontent:"| 3C |"; uricontent:"SCRIPT"; nocase; uricontent:"| 3E |"; reference:cve,CVE-2007-2914; reference:url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded; reference:url,doc.emergingthreats.net/2004587; classtype:web-application-attack; sid:2004587; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004587
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PsychoStats XSS Attempt -- awards.php"; flow:established,to_server; uricontent:"/awards.php?"; nocase; uricontent:"| 3C |"; uricontent:"SCRIPT"; nocase; uricontent:"| 3E |"; reference:cve,CVE-2007-2914; reference:url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded; reference:url,doc.emergingthreats.net/2004587; classtype:web-application-attack; sid:2004587; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PsychoStats XSS Attempt -- awards.php** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2914|url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded|url,doc.emergingthreats.net/2004587

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PsychoStats XSS Attempt -- login.php"; flow:established,to_server; uricontent:"/login.php?"; nocase; uricontent:"| 3C |"; uricontent:"SCRIPT"; nocase; uricontent:"| 3E |"; reference:cve,CVE-2007-2914; reference:url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded; reference:url,doc.emergingthreats.net/2004588; classtype:web-application-attack; sid:2004588; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004588
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PsychoStats XSS Attempt -- login.php"; flow:established,to_server; uricontent:"/login.php?"; nocase; uricontent:"| 3C |"; uricontent:"SCRIPT"; nocase; uricontent:"| 3E |"; reference:cve,CVE-2007-2914; reference:url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded; reference:url,doc.emergingthreats.net/2004588; classtype:web-application-attack; sid:2004588; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PsychoStats XSS Attempt -- login.php** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2914|url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded|url,doc.emergingthreats.net/2004588

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PsychoStats XSS Attempt -- register.php"; flow:established,to_server; uricontent:"/register.php?"; nocase; uricontent:"| 3C |"; uricontent:"SCRIPT"; nocase; uricontent:"| 3E |"; reference:cve,CVE-2007-2914; reference:url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded; reference:url,doc.emergingthreats.net/2004589; classtype:web-application-attack; sid:2004589; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004589
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PsychoStats XSS Attempt -- register.php"; flow:established,to_server; uricontent:"/register.php?"; nocase; uricontent:"| 3C |"; uricontent:"SCRIPT"; nocase; uricontent:"| 3E |"; reference:cve,CVE-2007-2914; reference:url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded; reference:url,doc.emergingthreats.net/2004589; classtype:web-application-attack; sid:2004589; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PsychoStats XSS Attempt -- register.php** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2914|url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded|url,doc.emergingthreats.net/2004589

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PsychoStats XSS Attempt -- weapons.php"; flow:established,to_server; uricontent:"/weapons.php?"; nocase; uricontent:"| 3C |"; uricontent:"SCRIPT"; nocase; uricontent:"| 3E |"; reference:cve,CVE-2007-2914; reference:url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded; reference:url,doc.emergingthreats.net/2004590; classtype:web-application-attack; sid:2004590; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004590
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PsychoStats XSS Attempt -- weapons.php"; flow:established,to_server; uricontent:"/weapons.php?"; nocase; uricontent:"| 3C |"; uricontent:"SCRIPT"; nocase; uricontent:"| 3E |"; reference:cve,CVE-2007-2914; reference:url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded; reference:url,doc.emergingthreats.net/2004590; classtype:web-application-attack; sid:2004590; rev:4; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PsychoStats XSS Attempt -- weapons.php** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2914|url,www.securityfocus.com/archive/1/archive/1/469260/100/0/threaded|url,doc.emergingthreats.net/2004590

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 4

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Quantum Game Library server_request.php CONFIG Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/server_request.php?"; nocase; uricontent:"CONFIG[gameroot]="; nocase; pcre:"/CONFIG\[gameroot\]=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,27945; reference:url,secunia.com/advisories/29077; reference:url,milw0rm.com/exploits/5174; reference:url,doc.emergingthreats.net/2009502; classtype:web-application-attack; sid:2009502; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009502
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Quantum Game Library server_request.php CONFIG Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/server_request.php?"; nocase; uricontent:"CONFIG[gameroot]="; nocase; pcre:"/CONFIG\[gameroot\]=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,27945; reference:url,secunia.com/advisories/29077; reference:url,milw0rm.com/exploits/5174; reference:url,doc.emergingthreats.net/2009502; classtype:web-application-attack; sid:2009502; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Quantum Game Library server_request.php CONFIG Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,27945|url,secunia.com/advisories/29077|url,milw0rm.com/exploits/5174|url,doc.emergingthreats.net/2009502

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Quantum Game Library smarty.inc.php CONFIG Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/qlib/smarty.inc.php?"; nocase; uricontent:"CONFIG[gameroot]="; nocase; pcre:"/CONFIG\[gameroot\]=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,27945; reference:url,secunia.com/advisories/29077; reference:url,milw0rm.com/exploits/5174; reference:url,doc.emergingthreats.net/2009504; classtype:web-application-attack; sid:2009504; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009504
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Quantum Game Library smarty.inc.php CONFIG Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/qlib/smarty.inc.php?"; nocase; uricontent:"CONFIG[gameroot]="; nocase; pcre:"/CONFIG\[gameroot\]=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,27945; reference:url,secunia.com/advisories/29077; reference:url,milw0rm.com/exploits/5174; reference:url,doc.emergingthreats.net/2009504; classtype:web-application-attack; sid:2009504; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Quantum Game Library smarty.inc.php CONFIG Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,27945|url,secunia.com/advisories/29077|url,milw0rm.com/exploits/5174|url,doc.emergingthreats.net/2009504

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS QuickTeam qte_web.php qte_web_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/qte_web.php?"; nocase; uricontent:"qte_web_path="; nocase; pcre:"/qte_web_path=\s*(ftps?|https?|php)\:\//Ui"; reference:url,secunia.com/advisories/34997/; reference:url,milw0rm.com/exploits/8602; reference:url,doc.emergingthreats.net/2009723; classtype:web-application-attack; sid:2009723; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009723
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS QuickTeam qte_web.php qte_web_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/qte_web.php?"; nocase; uricontent:"qte_web_path="; nocase; pcre:"/qte_web_path=\s*(ftps?|https?|php)\:\//Ui"; reference:url,secunia.com/advisories/34997/; reference:url,milw0rm.com/exploits/8602; reference:url,doc.emergingthreats.net/2009723; classtype:web-application-attack; sid:2009723; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **QuickTeam qte_web.php qte_web_path Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,secunia.com/advisories/34997/|url,milw0rm.com/exploits/8602|url,doc.emergingthreats.net/2009723

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RM EasyMail Plus XSS Attempt -- Login d"; flow:established,to_server; uricontent:"cp/ps/Main/login/Login"; nocase; uricontent:"d="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-2802; reference:url,www.secunia.com/advisories/25326; reference:url,doc.emergingthreats.net/2004571; classtype:web-application-attack; sid:2004571; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004571
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RM EasyMail Plus XSS Attempt -- Login d"; flow:established,to_server; uricontent:"cp/ps/Main/login/Login"; nocase; uricontent:"d="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-2802; reference:url,www.secunia.com/advisories/25326; reference:url,doc.emergingthreats.net/2004571; classtype:web-application-attack; sid:2004571; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RM EasyMail Plus XSS Attempt -- Login d** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2802|url,www.secunia.com/advisories/25326|url,doc.emergingthreats.net/2004571

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RSS-aggregator display.php path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/display.php?"; nocase; uricontent:"path="; nocase; pcre:"/path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,29873; reference:url,milw0rm.com/exploits/5900; reference:url,doc.emergingthreats.net/2009788; classtype:web-application-attack; sid:2009788; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009788
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RSS-aggregator display.php path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/display.php?"; nocase; uricontent:"path="; nocase; pcre:"/path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,29873; reference:url,milw0rm.com/exploits/5900; reference:url,doc.emergingthreats.net/2009788; classtype:web-application-attack; sid:2009788; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RSS-aggregator display.php path Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,29873|url,milw0rm.com/exploits/5900|url,doc.emergingthreats.net/2009788

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS REALTOR define.php Remote File Inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/define.php?"; nocase; uricontent:"INC_DIR="; nocase; pcre:"/INC_DIR=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,33227; reference:url,milw0rm.com/exploits/7743; reference:url,doc.emergingthreats.net/2009101; classtype:web-application-attack; sid:2009101; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009101
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS REALTOR define.php Remote File Inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/define.php?"; nocase; uricontent:"INC_DIR="; nocase; pcre:"/INC_DIR=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,33227; reference:url,milw0rm.com/exploits/7743; reference:url,doc.emergingthreats.net/2009101; classtype:web-application-attack; sid:2009101; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **REALTOR define.php Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,33227|url,milw0rm.com/exploits/7743|url,doc.emergingthreats.net/2009101

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Feederator add_tmsp.php mosConfig_absolute_path parameter remote file inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/tmsp/add_tmsp.php?"; nocase; uricontent:"mosConfig_absolute_path="; nocase; pcre:"/mosConfig_absolute_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32194; reference:url,milw0rm.com/exploits/7040; reference:url,doc.emergingthreats.net/2009059; classtype:web-application-attack; sid:2009059; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009059
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Feederator add_tmsp.php mosConfig_absolute_path parameter remote file inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/tmsp/add_tmsp.php?"; nocase; uricontent:"mosConfig_absolute_path="; nocase; pcre:"/mosConfig_absolute_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32194; reference:url,milw0rm.com/exploits/7040; reference:url,doc.emergingthreats.net/2009059; classtype:web-application-attack; sid:2009059; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Recly Feederator add_tmsp.php mosConfig_absolute_path parameter remote file inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32194|url,milw0rm.com/exploits/7040|url,doc.emergingthreats.net/2009059

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Feederator edit_tmsp.php mosConfig_absolute_path parameter remote file inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/tmsp/edit_tmsp.php?"; nocase; uricontent:"mosConfig_absolute_path="; nocase; pcre:"/mosConfig_absolute_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32194; reference:url,milw0rm.com/exploits/7040; reference:url,doc.emergingthreats.net/2009060; classtype:web-application-attack; sid:2009060; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009060
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Feederator edit_tmsp.php mosConfig_absolute_path parameter remote file inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/tmsp/edit_tmsp.php?"; nocase; uricontent:"mosConfig_absolute_path="; nocase; pcre:"/mosConfig_absolute_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32194; reference:url,milw0rm.com/exploits/7040; reference:url,doc.emergingthreats.net/2009060; classtype:web-application-attack; sid:2009060; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Recly Feederator edit_tmsp.php mosConfig_absolute_path parameter remote file inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32194|url,milw0rm.com/exploits/7040|url,doc.emergingthreats.net/2009060

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Feederator tmsp.php mosConfig_absolute_path parameter remote file inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/tmsp/tmsp.php?"; nocase; uricontent:"mosConfig_absolute_path="; nocase; pcre:"/mosConfig_absolute_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32194; reference:url,milw0rm.com/exploits/7040; reference:url,doc.emergingthreats.net/2009062; classtype:web-application-attack; sid:2009062; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009062
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Feederator tmsp.php mosConfig_absolute_path parameter remote file inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/tmsp/tmsp.php?"; nocase; uricontent:"mosConfig_absolute_path="; nocase; pcre:"/mosConfig_absolute_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32194; reference:url,milw0rm.com/exploits/7040; reference:url,doc.emergingthreats.net/2009062; classtype:web-application-attack; sid:2009062; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Recly Feederator tmsp.php mosConfig_absolute_path parameter remote file inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32194|url,milw0rm.com/exploits/7040|url,doc.emergingthreats.net/2009062

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Competitions Component add.php GLOBALS Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/competitions/add.php?"; nocase; uricontent:"GLOBALS[mosConfig_absolute_path]="; nocase; pcre:"/GLOBALS\[mosConfig_absolute_path\]=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32192; reference:url,milw0rm.com/exploits/7039; reference:url,doc.emergingthreats.net/2009466; classtype:web-application-attack; sid:2009466; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009466
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Competitions Component add.php GLOBALS Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/competitions/add.php?"; nocase; uricontent:"GLOBALS[mosConfig_absolute_path]="; nocase; pcre:"/GLOBALS\[mosConfig_absolute_path\]=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32192; reference:url,milw0rm.com/exploits/7039; reference:url,doc.emergingthreats.net/2009466; classtype:web-application-attack; sid:2009466; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Recly Competitions Component add.php GLOBALS Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32192|url,milw0rm.com/exploits/7039|url,doc.emergingthreats.net/2009466

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Competitions Component competitions.php GLOBALS Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/competitions/competitions.php?"; nocase; uricontent:"GLOBALS[mosConfig_absolute_path]="; nocase; pcre:"/GLOBALS\[mosConfig_absolute_path\]=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32192; reference:url,milw0rm.com/exploits/7039; reference:url,doc.emergingthreats.net/2009467; classtype:web-application-attack; sid:2009467; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009467
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Competitions Component competitions.php GLOBALS Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/competitions/competitions.php?"; nocase; uricontent:"GLOBALS[mosConfig_absolute_path]="; nocase; pcre:"/GLOBALS\[mosConfig_absolute_path\]=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32192; reference:url,milw0rm.com/exploits/7039; reference:url,doc.emergingthreats.net/2009467; classtype:web-application-attack; sid:2009467; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Recly Competitions Component competitions.php GLOBALS Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32192|url,milw0rm.com/exploits/7039|url,doc.emergingthreats.net/2009467

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Competitions Component settings.php mosConfig_absolute_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/settings/settings.php?"; nocase; uricontent:"mosConfig_absolute_path="; nocase; pcre:"/mosConfig_absolute_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32192; reference:url,milw0rm.com/exploits/7039; reference:url,doc.emergingthreats.net/2009468; classtype:web-application-attack; sid:2009468; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009468
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Recly Competitions Component settings.php mosConfig_absolute_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/includes/settings/settings.php?"; nocase; uricontent:"mosConfig_absolute_path="; nocase; pcre:"/mosConfig_absolute_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32192; reference:url,milw0rm.com/exploits/7039; reference:url,doc.emergingthreats.net/2009468; classtype:web-application-attack; sid:2009468; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Recly Competitions Component settings.php mosConfig_absolute_path Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32192|url,milw0rm.com/exploits/7039|url,doc.emergingthreats.net/2009468

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Redoable XSS Attempt -- searchloop.php s"; flow:established,to_server; uricontent:"/wp-content/themes/redoable/searchloop.php?"; nocase; uricontent:"s="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2757; reference:url,www.securityfocus.com/archive/1/archive/1/468892/100/0/threaded; reference:url,doc.emergingthreats.net/2003872; classtype:web-application-attack; sid:2003872; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003872
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Redoable XSS Attempt -- searchloop.php s"; flow:established,to_server; uricontent:"/wp-content/themes/redoable/searchloop.php?"; nocase; uricontent:"s="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2757; reference:url,www.securityfocus.com/archive/1/archive/1/468892/100/0/threaded; reference:url,doc.emergingthreats.net/2003872; classtype:web-application-attack; sid:2003872; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Redoable XSS Attempt -- searchloop.php s** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2757|url,www.securityfocus.com/archive/1/archive/1/468892/100/0/threaded|url,doc.emergingthreats.net/2003872

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Redoable XSS Attempt -- header.php s"; flow:established,to_server; uricontent:"/wp-content/themes/redoable/header.php?"; nocase; uricontent:"s="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2757; reference:url,www.securityfocus.com/archive/1/archive/1/468892/100/0/threaded; reference:url,doc.emergingthreats.net/2003873; classtype:web-application-attack; sid:2003873; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003873
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Redoable XSS Attempt -- header.php s"; flow:established,to_server; uricontent:"/wp-content/themes/redoable/header.php?"; nocase; uricontent:"s="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2757; reference:url,www.securityfocus.com/archive/1/archive/1/468892/100/0/threaded; reference:url,doc.emergingthreats.net/2003873; classtype:web-application-attack; sid:2003873; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Redoable XSS Attempt -- header.php s** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2757|url,www.securityfocus.com/archive/1/archive/1/468892/100/0/threaded|url,doc.emergingthreats.net/2003873

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv SELECT"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"SELECT"; nocase; uricontent:"FROM"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003829; classtype:web-application-attack; sid:2003829; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003829
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv SELECT"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"SELECT"; nocase; uricontent:"FROM"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003829; classtype:web-application-attack; sid:2003829; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ResManager SQL Injection Attempt -- edit_day.php id_reserv SELECT** 

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

URL reference : cve,CVE-2007-2735|url,www.milw0rm.com/exploits/3931|url,doc.emergingthreats.net/2003829

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv UNION SELECT"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003830; classtype:web-application-attack; sid:2003830; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003830
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv UNION SELECT"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003830; classtype:web-application-attack; sid:2003830; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ResManager SQL Injection Attempt -- edit_day.php id_reserv UNION SELECT** 

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

URL reference : cve,CVE-2007-2735|url,www.milw0rm.com/exploits/3931|url,doc.emergingthreats.net/2003830

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv INSERT"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003831; classtype:web-application-attack; sid:2003831; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003831
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv INSERT"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003831; classtype:web-application-attack; sid:2003831; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ResManager SQL Injection Attempt -- edit_day.php id_reserv INSERT** 

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

URL reference : cve,CVE-2007-2735|url,www.milw0rm.com/exploits/3931|url,doc.emergingthreats.net/2003831

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv DELETE"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003832; classtype:web-application-attack; sid:2003832; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003832
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv DELETE"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003832; classtype:web-application-attack; sid:2003832; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ResManager SQL Injection Attempt -- edit_day.php id_reserv DELETE** 

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

URL reference : cve,CVE-2007-2735|url,www.milw0rm.com/exploits/3931|url,doc.emergingthreats.net/2003832

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv ASCII"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003833; classtype:web-application-attack; sid:2003833; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003833
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv ASCII"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003833; classtype:web-application-attack; sid:2003833; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ResManager SQL Injection Attempt -- edit_day.php id_reserv ASCII** 

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

URL reference : cve,CVE-2007-2735|url,www.milw0rm.com/exploits/3931|url,doc.emergingthreats.net/2003833

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv UPDATE"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003834; classtype:web-application-attack; sid:2003834; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003834
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ResManager SQL Injection Attempt -- edit_day.php id_reserv UPDATE"; flow:established,to_server; uricontent:"/edit_day.php?"; nocase; uricontent:"id_reserv="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2735; reference:url,www.milw0rm.com/exploits/3931; reference:url,doc.emergingthreats.net/2003834; classtype:web-application-attack; sid:2003834; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ResManager SQL Injection Attempt -- edit_day.php id_reserv UPDATE** 

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

URL reference : cve,CVE-2007-2735|url,www.milw0rm.com/exploits/3931|url,doc.emergingthreats.net/2003834

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Text Lines Rearrange Script filename parameter File Disclosure"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/download.php?"; nocase; uricontent:"filename="; nocase; pcre:"/(\.\.\/){1,}/U"; reference:url,securityfocus.com/bid/32968; reference:url,milw0rm.com/exploits/7542; reference:url,doc.emergingthreats.net/2009018; classtype:web-application-attack; sid:2009018; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009018
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Text Lines Rearrange Script filename parameter File Disclosure"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/download.php?"; nocase; uricontent:"filename="; nocase; pcre:"/(\.\.\/){1,}/U"; reference:url,securityfocus.com/bid/32968; reference:url,milw0rm.com/exploits/7542; reference:url,doc.emergingthreats.net/2009018; classtype:web-application-attack; sid:2009018; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Text Lines Rearrange Script filename parameter File Disclosure** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,securityfocus.com/bid/32968|url,milw0rm.com/exploits/7542|url,doc.emergingthreats.net/2009018

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004660; classtype:web-application-attack; sid:2004660; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004660
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004660; classtype:web-application-attack; sid:2004660; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria SELECT** 

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

URL reference : cve,CVE-2007-1293|url,www.milw0rm.com/exploits/3403|url,doc.emergingthreats.net/2004660

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004661; classtype:web-application-attack; sid:2004661; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004661
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004661; classtype:web-application-attack; sid:2004661; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria UNION SELECT** 

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

URL reference : cve,CVE-2007-1293|url,www.milw0rm.com/exploits/3403|url,doc.emergingthreats.net/2004661

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004662; classtype:web-application-attack; sid:2004662; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004662
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004662; classtype:web-application-attack; sid:2004662; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria INSERT** 

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

URL reference : cve,CVE-2007-1293|url,www.milw0rm.com/exploits/3403|url,doc.emergingthreats.net/2004662

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004663; classtype:web-application-attack; sid:2004663; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004663
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004663; classtype:web-application-attack; sid:2004663; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria DELETE** 

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

URL reference : cve,CVE-2007-1293|url,www.milw0rm.com/exploits/3403|url,doc.emergingthreats.net/2004663

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004664; classtype:web-application-attack; sid:2004664; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004664
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004664; classtype:web-application-attack; sid:2004664; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria ASCII** 

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

URL reference : cve,CVE-2007-1293|url,www.milw0rm.com/exploits/3403|url,doc.emergingthreats.net/2004664

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004665; classtype:web-application-attack; sid:2004665; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004665
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"categoria="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-1293; reference:url,www.milw0rm.com/exploits/3403; reference:url,doc.emergingthreats.net/2004665; classtype:web-application-attack; sid:2004665; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Rigter Portal System (RPS) SQL Injection Attempt -- index.php categoria UPDATE** 

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

URL reference : cve,CVE-2007-1293|url,www.milw0rm.com/exploits/3403|url,doc.emergingthreats.net/2004665

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Ripe Website Manager XSS Attempt -- index.php ripeformpost"; flow:established,to_server; uricontent:"/contact/index.php?"; nocase; uricontent:"ripeformpost="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2206; reference:url,www.securityfocus.com/bid/23597; reference:url,doc.emergingthreats.net/2003871; classtype:web-application-attack; sid:2003871; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003871
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Ripe Website Manager XSS Attempt -- index.php ripeformpost"; flow:established,to_server; uricontent:"/contact/index.php?"; nocase; uricontent:"ripeformpost="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2206; reference:url,www.securityfocus.com/bid/23597; reference:url,doc.emergingthreats.net/2003871; classtype:web-application-attack; sid:2003871; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Ripe Website Manager XSS Attempt -- index.php ripeformpost** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2206|url,www.securityfocus.com/bid/23597|url,doc.emergingthreats.net/2003871

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries SELECT"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"SELECT"; nocase; uricontent:"FROM"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003817; classtype:web-application-attack; sid:2003817; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003817
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries SELECT"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"SELECT"; nocase; uricontent:"FROM"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003817; classtype:web-application-attack; sid:2003817; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunCms SQL Injection Attempt -- debug_show.php executed_queries SELECT** 

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

URL reference : cve,CVE-2007-2538|url,www.milw0rm.com/exploits/3850|url,doc.emergingthreats.net/2003817

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries UNION SELECT"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003818; classtype:web-application-attack; sid:2003818; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003818
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries UNION SELECT"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003818; classtype:web-application-attack; sid:2003818; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunCms SQL Injection Attempt -- debug_show.php executed_queries UNION SELECT** 

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

URL reference : cve,CVE-2007-2538|url,www.milw0rm.com/exploits/3850|url,doc.emergingthreats.net/2003818

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries INSERT"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003819; classtype:web-application-attack; sid:2003819; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003819
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries INSERT"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003819; classtype:web-application-attack; sid:2003819; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunCms SQL Injection Attempt -- debug_show.php executed_queries INSERT** 

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

URL reference : cve,CVE-2007-2538|url,www.milw0rm.com/exploits/3850|url,doc.emergingthreats.net/2003819

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries DELETE"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003820; classtype:web-application-attack; sid:2003820; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003820
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries DELETE"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003820; classtype:web-application-attack; sid:2003820; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunCms SQL Injection Attempt -- debug_show.php executed_queries DELETE** 

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

URL reference : cve,CVE-2007-2538|url,www.milw0rm.com/exploits/3850|url,doc.emergingthreats.net/2003820

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries ASCII"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003821; classtype:web-application-attack; sid:2003821; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003821
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries ASCII"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003821; classtype:web-application-attack; sid:2003821; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunCms SQL Injection Attempt -- debug_show.php executed_queries ASCII** 

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

URL reference : cve,CVE-2007-2538|url,www.milw0rm.com/exploits/3850|url,doc.emergingthreats.net/2003821

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries UPDATE"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; nocase; uricontent:"UPDATE"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003822; classtype:web-application-attack; sid:2003822; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003822
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunCms SQL Injection Attempt -- debug_show.php executed_queries UPDATE"; flow:established,to_server; uricontent:"/class/debug/debug_show.php?"; nocase; uricontent:"executed_queries="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; nocase; uricontent:"UPDATE"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2538; reference:url,www.milw0rm.com/exploits/3850; reference:url,doc.emergingthreats.net/2003822; classtype:web-application-attack; sid:2003822; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunCms SQL Injection Attempt -- debug_show.php executed_queries UPDATE** 

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

URL reference : cve,CVE-2007-2538|url,www.milw0rm.com/exploits/3850|url,doc.emergingthreats.net/2003822

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id SELECT"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003858; classtype:web-application-attack; sid:2003858; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003858
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id SELECT"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003858; classtype:web-application-attack; sid:2003858; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id SELECT** 

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

URL reference : cve,CVE-2007-2752|url,www.milw0rm.com/exploits/3936|url,doc.emergingthreats.net/2003858

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id UNION SELECT"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003859; classtype:web-application-attack; sid:2003859; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003859
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id UNION SELECT"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003859; classtype:web-application-attack; sid:2003859; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id UNION SELECT** 

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

URL reference : cve,CVE-2007-2752|url,www.milw0rm.com/exploits/3936|url,doc.emergingthreats.net/2003859

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id INSERT"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003860; classtype:web-application-attack; sid:2003860; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003860
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id INSERT"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003860; classtype:web-application-attack; sid:2003860; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id INSERT** 

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

URL reference : cve,CVE-2007-2752|url,www.milw0rm.com/exploits/3936|url,doc.emergingthreats.net/2003860

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id DELETE"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003861; classtype:web-application-attack; sid:2003861; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003861
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id DELETE"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003861; classtype:web-application-attack; sid:2003861; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id DELETE** 

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

URL reference : cve,CVE-2007-2752|url,www.milw0rm.com/exploits/3936|url,doc.emergingthreats.net/2003861

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id ASCII"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003862; classtype:web-application-attack; sid:2003862; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003862
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id ASCII"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003862; classtype:web-application-attack; sid:2003862; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id ASCII** 

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

URL reference : cve,CVE-2007-2752|url,www.milw0rm.com/exploits/3936|url,doc.emergingthreats.net/2003862

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id UPDATE"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003863; classtype:web-application-attack; sid:2003863; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003863
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id UPDATE"; flow:established,to_server; uricontent:"/devami.asp?"; nocase; uricontent:"id="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2752; reference:url,www.milw0rm.com/exploits/3936; reference:url,doc.emergingthreats.net/2003863; classtype:web-application-attack; sid:2003863; rev:6; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **RunawaySoft Haber portal 1.0 SQL Injection Attempt -- devami.asp id UPDATE** 

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

URL reference : cve,CVE-2007-2752|url,www.milw0rm.com/exploits/3936|url,doc.emergingthreats.net/2003863

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SMA-DB format.php _page_css Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/theme/format.php?"; nocase; uricontent:"_page_css="; nocase; pcre:"/_page_css=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,34569; reference:url,milw0rm.com/exploits/8460; reference:url,doc.emergingthreats.net/2009653; classtype:web-application-attack; sid:2009653; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009653
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SMA-DB format.php _page_css Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/theme/format.php?"; nocase; uricontent:"_page_css="; nocase; pcre:"/_page_css=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,34569; reference:url,milw0rm.com/exploits/8460; reference:url,doc.emergingthreats.net/2009653; classtype:web-application-attack; sid:2009653; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SMA-DB format.php _page_css Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,34569|url,milw0rm.com/exploits/8460|url,doc.emergingthreats.net/2009653

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SMA-DB format.php _page_javascript Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/theme/format.php?"; nocase; uricontent:"_page_javascript="; nocase; pcre:"/_page_javascript=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,34569; reference:url,milw0rm.com/exploits/8460; reference:url,doc.emergingthreats.net/2009654; classtype:web-application-attack; sid:2009654; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009654
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SMA-DB format.php _page_javascript Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/theme/format.php?"; nocase; uricontent:"_page_javascript="; nocase; pcre:"/_page_javascript=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,34569; reference:url,milw0rm.com/exploits/8460; reference:url,doc.emergingthreats.net/2009654; classtype:web-application-attack; sid:2009654; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SMA-DB format.php _page_javascript Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,34569|url,milw0rm.com/exploits/8460|url,doc.emergingthreats.net/2009654

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SMA-DB format.php _page_content Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/theme/format.php?"; nocase; uricontent:"_page_content="; nocase; pcre:"/_page_content=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,34569; reference:url,milw0rm.com/exploits/8460; reference:url,doc.emergingthreats.net/2009656; classtype:web-application-attack; sid:2009656; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009656
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SMA-DB format.php _page_content Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/theme/format.php?"; nocase; uricontent:"_page_content="; nocase; pcre:"/_page_content=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,34569; reference:url,milw0rm.com/exploits/8460; reference:url,doc.emergingthreats.net/2009656; classtype:web-application-attack; sid:2009656; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SMA-DB format.php _page_content Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,34569|url,milw0rm.com/exploits/8460|url,doc.emergingthreats.net/2009656

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004116; classtype:web-application-attack; sid:2004116; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004116
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004116; classtype:web-application-attack; sid:2004116; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ScriptMagix Jokes SQL Injection Attempt -- index.php catid SELECT** 

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

URL reference : cve,CVE-2007-1615|url,www.milw0rm.com/exploits/3509|url,doc.emergingthreats.net/2004116

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004117; classtype:web-application-attack; sid:2004117; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004117
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004117; classtype:web-application-attack; sid:2004117; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ScriptMagix Jokes SQL Injection Attempt -- index.php catid UNION SELECT** 

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

URL reference : cve,CVE-2007-1615|url,www.milw0rm.com/exploits/3509|url,doc.emergingthreats.net/2004117

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004118; classtype:web-application-attack; sid:2004118; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004118
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004118; classtype:web-application-attack; sid:2004118; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ScriptMagix Jokes SQL Injection Attempt -- index.php catid INSERT** 

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

URL reference : cve,CVE-2007-1615|url,www.milw0rm.com/exploits/3509|url,doc.emergingthreats.net/2004118

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004119; classtype:web-application-attack; sid:2004119; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004119
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004119; classtype:web-application-attack; sid:2004119; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ScriptMagix Jokes SQL Injection Attempt -- index.php catid DELETE** 

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

URL reference : cve,CVE-2007-1615|url,www.milw0rm.com/exploits/3509|url,doc.emergingthreats.net/2004119

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004120; classtype:web-application-attack; sid:2004120; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004120
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004120; classtype:web-application-attack; sid:2004120; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ScriptMagix Jokes SQL Injection Attempt -- index.php catid ASCII** 

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

URL reference : cve,CVE-2007-1615|url,www.milw0rm.com/exploits/3509|url,doc.emergingthreats.net/2004120

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004121; classtype:web-application-attack; sid:2004121; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004121
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ScriptMagix Jokes SQL Injection Attempt -- index.php catid UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"catid="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-1615; reference:url,www.milw0rm.com/exploits/3509; reference:url,doc.emergingthreats.net/2004121; classtype:web-application-attack; sid:2004121; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ScriptMagix Jokes SQL Injection Attempt -- index.php catid UPDATE** 

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

URL reference : cve,CVE-2007-1615|url,www.milw0rm.com/exploits/3509|url,doc.emergingthreats.net/2004121

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Sendcard XSS Attempt -- sendcard.php form"; flow:established,to_server; uricontent:"/sendcard.php?"; nocase; uricontent:"form="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2472; reference:url,www.secunia.com/advisories/25085; reference:url,doc.emergingthreats.net/2003922; classtype:web-application-attack; sid:2003922; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003922
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Sendcard XSS Attempt -- sendcard.php form"; flow:established,to_server; uricontent:"/sendcard.php?"; nocase; uricontent:"form="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2472; reference:url,www.secunia.com/advisories/25085; reference:url,doc.emergingthreats.net/2003922; classtype:web-application-attack; sid:2003922; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Sendcard XSS Attempt -- sendcard.php form** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2472|url,www.secunia.com/advisories/25085|url,doc.emergingthreats.net/2003922

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SezHoo SezHooTabsAndActions.php IP Parameter Remote File Inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/SezHooTabsAndActions.php?"; nocase; uricontent:"IP="; nocase; pcre:"/IP=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,31756; reference:url,www.milw0rm.com/exploits/6751; reference:url,doc.emergingthreats.net/2009123; classtype:web-application-attack; sid:2009123; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009123
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SezHoo SezHooTabsAndActions.php IP Parameter Remote File Inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/SezHooTabsAndActions.php?"; nocase; uricontent:"IP="; nocase; pcre:"/IP=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,31756; reference:url,www.milw0rm.com/exploits/6751; reference:url,doc.emergingthreats.net/2009123; classtype:web-application-attack; sid:2009123; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SezHoo SezHooTabsAndActions.php IP Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,31756|url,www.milw0rm.com/exploits/6751|url,doc.emergingthreats.net/2009123

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr SELECT"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"SELECT"; nocase; uricontent:"FROM"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003852; classtype:web-application-attack; sid:2003852; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003852
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr SELECT"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"SELECT"; nocase; uricontent:"FROM"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003852; classtype:web-application-attack; sid:2003852; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SimpNews SQL Injection Attempt -- print.php newsnr SELECT** 

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

URL reference : cve,CVE-2007-2750|url,www.milw0rm.com/exploits/3942|url,doc.emergingthreats.net/2003852

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr UNION SELECT"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003853; classtype:web-application-attack; sid:2003853; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003853
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr UNION SELECT"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003853; classtype:web-application-attack; sid:2003853; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SimpNews SQL Injection Attempt -- print.php newsnr UNION SELECT** 

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

URL reference : cve,CVE-2007-2750|url,www.milw0rm.com/exploits/3942|url,doc.emergingthreats.net/2003853

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr INSERT"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003854; classtype:web-application-attack; sid:2003854; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003854
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr INSERT"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"INSERT"; nocase; uricontent:"INTO"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003854; classtype:web-application-attack; sid:2003854; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SimpNews SQL Injection Attempt -- print.php newsnr INSERT** 

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

URL reference : cve,CVE-2007-2750|url,www.milw0rm.com/exploits/3942|url,doc.emergingthreats.net/2003854

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr DELETE"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003855; classtype:web-application-attack; sid:2003855; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003855
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr DELETE"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"DELETE"; nocase; uricontent:"FROM"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003855; classtype:web-application-attack; sid:2003855; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SimpNews SQL Injection Attempt -- print.php newsnr DELETE** 

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

URL reference : cve,CVE-2007-2750|url,www.milw0rm.com/exploits/3942|url,doc.emergingthreats.net/2003855

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr ASCII"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003856; classtype:web-application-attack; sid:2003856; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003856
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr ASCII"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"ASCII("; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003856; classtype:web-application-attack; sid:2003856; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SimpNews SQL Injection Attempt -- print.php newsnr ASCII** 

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

URL reference : cve,CVE-2007-2750|url,www.milw0rm.com/exploits/3942|url,doc.emergingthreats.net/2003856

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr UPDATE"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003857; classtype:web-application-attack; sid:2003857; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003857
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SimpNews SQL Injection Attempt -- print.php newsnr UPDATE"; flow:established,to_server; uricontent:"/print.php?"; nocase; uricontent:"newsnr="; nocase; uricontent:"UPDATE"; nocase; uricontent:"SET"; nocase; pcre:"/.+UPDATE.+SET/Ui"; reference:cve,CVE-2007-2750; reference:url,www.milw0rm.com/exploits/3942; reference:url,doc.emergingthreats.net/2003857; classtype:web-application-attack; sid:2003857; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SimpNews SQL Injection Attempt -- print.php newsnr UPDATE** 

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

URL reference : cve,CVE-2007-2750|url,www.milw0rm.com/exploits/3942|url,doc.emergingthreats.net/2003857

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Simple PHP Script Gallery Remote Inclusion index.php gallery"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"gallery="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2679; reference:url,www.securityfocus.com/bid/23534; reference:url,doc.emergingthreats.net/2003746; classtype:web-application-attack; sid:2003746; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003746
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Simple PHP Script Gallery Remote Inclusion index.php gallery"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"gallery="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2679; reference:url,www.securityfocus.com/bid/23534; reference:url,doc.emergingthreats.net/2003746; classtype:web-application-attack; sid:2003746; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Simple PHP Script Gallery Remote Inclusion index.php gallery** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2679|url,www.securityfocus.com/bid/23534|url,doc.emergingthreats.net/2003746

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Simple Text-File Login script slogin_path parameter remote file inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/slogin_lib.inc.php?"; nocase; uricontent:"slogin_path="; nocase; pcre:"/slogin_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32811; reference:url,milw0rm.com/exploits/7444; reference:url,doc.emergingthreats.net/2008996; classtype:web-application-attack; sid:2008996; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2008996
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Simple Text-File Login script slogin_path parameter remote file inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/slogin_lib.inc.php?"; nocase; uricontent:"slogin_path="; nocase; pcre:"/slogin_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32811; reference:url,milw0rm.com/exploits/7444; reference:url,doc.emergingthreats.net/2008996; classtype:web-application-attack; sid:2008996; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Simple Text-File Login script slogin_path parameter remote file inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32811|url,milw0rm.com/exploits/7444|url,doc.emergingthreats.net/2008996

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005518; classtype:web-application-attack; sid:2005518; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005518
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005518; classtype:web-application-attack; sid:2005518; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php ps SELECT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005518

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005519; classtype:web-application-attack; sid:2005519; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005519
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005519; classtype:web-application-attack; sid:2005519; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php ps UNION SELECT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005519

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005520; classtype:web-application-attack; sid:2005520; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005520
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005520; classtype:web-application-attack; sid:2005520; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php ps INSERT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005520

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005521; classtype:web-application-attack; sid:2005521; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005521
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005521; classtype:web-application-attack; sid:2005521; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php ps DELETE** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005521

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005522; classtype:web-application-attack; sid:2005522; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005522
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005522; classtype:web-application-attack; sid:2005522; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php ps ASCII** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005522

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005523; classtype:web-application-attack; sid:2005523; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005523
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php ps UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"ps="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005523; classtype:web-application-attack; sid:2005523; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php ps UPDATE** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005523

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php us SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"us="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005524; classtype:web-application-attack; sid:2005524; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005524
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php us SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"us="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005524; classtype:web-application-attack; sid:2005524; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php us SELECT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005524

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php us UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"us="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005525; classtype:web-application-attack; sid:2005525; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005525
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php us UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"us="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005525; classtype:web-application-attack; sid:2005525; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php us UNION SELECT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005525

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php us DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"us="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005527; classtype:web-application-attack; sid:2005527; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005527
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php us DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"us="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005527; classtype:web-application-attack; sid:2005527; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php us DELETE** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005527

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php us ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"us="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005528; classtype:web-application-attack; sid:2005528; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005528
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php us ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"us="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005528; classtype:web-application-attack; sid:2005528; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php us ASCII** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005528

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php us UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"us="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005529; classtype:web-application-attack; sid:2005529; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005529
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php us UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"us="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005529; classtype:web-application-attack; sid:2005529; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php us UPDATE** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005529

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005530; classtype:web-application-attack; sid:2005530; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005530
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005530; classtype:web-application-attack; sid:2005530; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php f SELECT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005530

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005531; classtype:web-application-attack; sid:2005531; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005531
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005531; classtype:web-application-attack; sid:2005531; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php f UNION SELECT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005531

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005532; classtype:web-application-attack; sid:2005532; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005532
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005532; classtype:web-application-attack; sid:2005532; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php f INSERT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005532

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005533; classtype:web-application-attack; sid:2005533; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005533
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005533; classtype:web-application-attack; sid:2005533; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php f DELETE** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005533

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005534; classtype:web-application-attack; sid:2005534; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005534
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005534; classtype:web-application-attack; sid:2005534; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php f ASCII** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005534

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005535; classtype:web-application-attack; sid:2005535; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005535
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php f UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"f="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005535; classtype:web-application-attack; sid:2005535; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php f UPDATE** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005535

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005536; classtype:web-application-attack; sid:2005536; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005536
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005536; classtype:web-application-attack; sid:2005536; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php code SELECT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005536

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005537; classtype:web-application-attack; sid:2005537; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005537
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005537; classtype:web-application-attack; sid:2005537; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php code UNION SELECT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005537

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005538; classtype:web-application-attack; sid:2005538; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005538
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005538; classtype:web-application-attack; sid:2005538; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php code INSERT** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005538

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005539; classtype:web-application-attack; sid:2005539; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005539
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005539; classtype:web-application-attack; sid:2005539; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php code DELETE** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005539

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005540; classtype:web-application-attack; sid:2005540; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005540
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005540; classtype:web-application-attack; sid:2005540; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php code ASCII** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005540

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005541; classtype:web-application-attack; sid:2005541; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005541
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SmE FileMailer SQL Injection Attempt -- index.php code UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"code="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-0350; reference:url,www.frsirt.com/english/advisories/2007/0221; reference:url,doc.emergingthreats.net/2005541; classtype:web-application-attack; sid:2005541; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SmE FileMailer SQL Injection Attempt -- index.php code UPDATE** 

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

URL reference : cve,CVE-2007-0350|url,www.frsirt.com/english/advisories/2007/0221|url,doc.emergingthreats.net/2005541

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SnippetMaster pcltar.lib.php g_pcltar_lib_dir Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/pcltar.lib.php?"; nocase; uricontent:"g_pcltar_lib_dir="; pcre:"/g_pcltar_lib_dir=\s*(https?|ftps?|php)\:\//Ui"; reference:url,secunia.com/advisories/33865/; reference:url,milw0rm.com/exploits/8017; reference:url,doc.emergingthreats.net/2009180; classtype:web-application-attack; sid:2009180; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009180
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SnippetMaster pcltar.lib.php g_pcltar_lib_dir Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/pcltar.lib.php?"; nocase; uricontent:"g_pcltar_lib_dir="; pcre:"/g_pcltar_lib_dir=\s*(https?|ftps?|php)\:\//Ui"; reference:url,secunia.com/advisories/33865/; reference:url,milw0rm.com/exploits/8017; reference:url,doc.emergingthreats.net/2009180; classtype:web-application-attack; sid:2009180; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SnippetMaster pcltar.lib.php g_pcltar_lib_dir Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,secunia.com/advisories/33865/|url,milw0rm.com/exploits/8017|url,doc.emergingthreats.net/2009180

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SonicBB XSS Attempt -- search.php part"; flow:established,to_server; uricontent:"/search.php?"; nocase; uricontent:"part="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-1903; reference:url,www.netvigilance.com/advisory0020; reference:url,doc.emergingthreats.net/2003881; classtype:web-application-attack; sid:2003881; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003881
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS SonicBB XSS Attempt -- search.php part"; flow:established,to_server; uricontent:"/search.php?"; nocase; uricontent:"part="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-1903; reference:url,www.netvigilance.com/advisory0020; reference:url,doc.emergingthreats.net/2003881; classtype:web-application-attack; sid:2003881; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **SonicBB XSS Attempt -- search.php part** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-1903|url,www.netvigilance.com/advisory0020|url,doc.emergingthreats.net/2003881

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004379; classtype:web-application-attack; sid:2004379; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004379
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004379; classtype:web-application-attack; sid:2004379; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Triexa SonicMailer Pro SQL Injection Attempt -- index.php list SELECT** 

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

URL reference : cve,CVE-2007-1425|url,www.milw0rm.com/exploits/3457|url,doc.emergingthreats.net/2004379

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004380; classtype:web-application-attack; sid:2004380; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004380
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004380; classtype:web-application-attack; sid:2004380; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Triexa SonicMailer Pro SQL Injection Attempt -- index.php list UNION SELECT** 

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

URL reference : cve,CVE-2007-1425|url,www.milw0rm.com/exploits/3457|url,doc.emergingthreats.net/2004380

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004381; classtype:web-application-attack; sid:2004381; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004381
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004381; classtype:web-application-attack; sid:2004381; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Triexa SonicMailer Pro SQL Injection Attempt -- index.php list INSERT** 

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

URL reference : cve,CVE-2007-1425|url,www.milw0rm.com/exploits/3457|url,doc.emergingthreats.net/2004381

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004382; classtype:web-application-attack; sid:2004382; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004382
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004382; classtype:web-application-attack; sid:2004382; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Triexa SonicMailer Pro SQL Injection Attempt -- index.php list DELETE** 

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

URL reference : cve,CVE-2007-1425|url,www.milw0rm.com/exploits/3457|url,doc.emergingthreats.net/2004382

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004383; classtype:web-application-attack; sid:2004383; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004383
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004383; classtype:web-application-attack; sid:2004383; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Triexa SonicMailer Pro SQL Injection Attempt -- index.php list ASCII** 

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

URL reference : cve,CVE-2007-1425|url,www.milw0rm.com/exploits/3457|url,doc.emergingthreats.net/2004383

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004384; classtype:web-application-attack; sid:2004384; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004384
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Triexa SonicMailer Pro SQL Injection Attempt -- index.php list UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"list="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-1425; reference:url,www.milw0rm.com/exploits/3457; reference:url,doc.emergingthreats.net/2004384; classtype:web-application-attack; sid:2004384; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Triexa SonicMailer Pro SQL Injection Attempt -- index.php list UPDATE** 

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

URL reference : cve,CVE-2007-1425|url,www.milw0rm.com/exploits/3457|url,doc.emergingthreats.net/2004384

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Synactis All_IN_THE_BOX ActiveX SaveDoc Method Arbitrary File Overwrite"; flow:to_client,established; content:"clsid"; nocase; content:"B5576893-F948-4E0F-9BE1-A37CB56D66FF"; nocase; distance:0; content:"SaveDoc"; nocase; reference:url,milw0rm.com/exploits/7928; reference:bugtraq,33535; reference:url,doc.emergingthreats.net/2009138; classtype:web-application-attack; sid:2009138; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)

# 2009138
`alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Synactis All_IN_THE_BOX ActiveX SaveDoc Method Arbitrary File Overwrite"; flow:to_client,established; content:"clsid"; nocase; content:"B5576893-F948-4E0F-9BE1-A37CB56D66FF"; nocase; distance:0; content:"SaveDoc"; nocase; reference:url,milw0rm.com/exploits/7928; reference:bugtraq,33535; reference:url,doc.emergingthreats.net/2009138; classtype:web-application-attack; sid:2009138; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2010_07_30, updated_at 2016_07_01;)
` 

Name : **Synactis All_IN_THE_BOX ActiveX SaveDoc Method Arbitrary File Overwrite** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/7928|bugtraq,33535|url,doc.emergingthreats.net/2009138

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2016-07-01

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion site_conf.php ordnertiefe"; flow:established,to_server; uricontent:"/site_conf.php?"; nocase; uricontent:"ordnertiefe="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003705; classtype:web-application-attack; sid:2003705; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003705
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion site_conf.php ordnertiefe"; flow:established,to_server; uricontent:"/site_conf.php?"; nocase; uricontent:"ordnertiefe="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003705; classtype:web-application-attack; sid:2003705; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion site_conf.php ordnertiefe** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003705

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion class.csv.php tt_docroot"; flow:established,to_server; uricontent:"/class.csv.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003706; classtype:web-application-attack; sid:2003706; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003706
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion class.csv.php tt_docroot"; flow:established,to_server; uricontent:"/class.csv.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003706; classtype:web-application-attack; sid:2003706; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion class.csv.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003706

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion produkte_nach_serie.php tt_docroot"; flow:established,to_server; uricontent:"/produkte_nach_serie.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003707; classtype:web-application-attack; sid:2003707; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003707
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion produkte_nach_serie.php tt_docroot"; flow:established,to_server; uricontent:"/produkte_nach_serie.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003707; classtype:web-application-attack; sid:2003707; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion produkte_nach_serie.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003707

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion ref_kd_rubrik.php tt_docroot"; flow:established,to_server; uricontent:"/functionen/ref_kd_rubrik.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003708; classtype:web-application-attack; sid:2003708; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003708
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion ref_kd_rubrik.php tt_docroot"; flow:established,to_server; uricontent:"/functionen/ref_kd_rubrik.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003708; classtype:web-application-attack; sid:2003708; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion ref_kd_rubrik.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003708

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion hg_referenz_jobgalerie.php tt_docroot"; flow:established,to_server; uricontent:"/hg_referenz_jobgalerie.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003709; classtype:web-application-attack; sid:2003709; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003709
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion hg_referenz_jobgalerie.php tt_docroot"; flow:established,to_server; uricontent:"/hg_referenz_jobgalerie.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003709; classtype:web-application-attack; sid:2003709; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion hg_referenz_jobgalerie.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003709

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion surfer_anmeldung_NWL.php tt_docroot"; flow:established,to_server; uricontent:"/surfer_anmeldung_NWL.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003710; classtype:web-application-attack; sid:2003710; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003710
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion surfer_anmeldung_NWL.php tt_docroot"; flow:established,to_server; uricontent:"/surfer_anmeldung_NWL.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003710; classtype:web-application-attack; sid:2003710; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion surfer_anmeldung_NWL.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003710

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion produkte_nach_serie_alle.php tt_docroot"; flow:established,to_server; uricontent:"/produkte_nach_serie_alle.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003711; classtype:web-application-attack; sid:2003711; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003711
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion produkte_nach_serie_alle.php tt_docroot"; flow:established,to_server; uricontent:"/produkte_nach_serie_alle.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003711; classtype:web-application-attack; sid:2003711; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion produkte_nach_serie_alle.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003711

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion surfer_aendern.php tt_docroot"; flow:established,to_server; uricontent:"/surfer_aendern.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003712; classtype:web-application-attack; sid:2003712; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003712
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion surfer_aendern.php tt_docroot"; flow:established,to_server; uricontent:"/surfer_aendern.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003712; classtype:web-application-attack; sid:2003712; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion surfer_aendern.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003712

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion ref_kd_rubrik.php tt_docroot"; flow:established,to_server; uricontent:"/ref_kd_rubrik.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003715; classtype:web-application-attack; sid:2003715; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003715
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion ref_kd_rubrik.php tt_docroot"; flow:established,to_server; uricontent:"/ref_kd_rubrik.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003715; classtype:web-application-attack; sid:2003715; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion ref_kd_rubrik.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003715

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion referenz.php tt_docroot"; flow:established,to_server; uricontent:"/module/referenz.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003713; classtype:web-application-attack; sid:2003713; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003713
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion referenz.php tt_docroot"; flow:established,to_server; uricontent:"/module/referenz.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003713; classtype:web-application-attack; sid:2003713; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion referenz.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003713

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion lay.php tt_docroot"; flow:established,to_server; uricontent:"/standard/1/lay.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003714; classtype:web-application-attack; sid:2003714; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003714
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion lay.php tt_docroot"; flow:established,to_server; uricontent:"/standard/1/lay.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003714; classtype:web-application-attack; sid:2003714; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion lay.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003714

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion 3_lay.php tt_docroot"; flow:established,to_server; uricontent:"/standard/3/lay.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003867; classtype:web-application-attack; sid:2003867; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003867
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TellTarget CMS Remote Inclusion 3_lay.php tt_docroot"; flow:established,to_server; uricontent:"/standard/3/lay.php?"; nocase; uricontent:"tt_docroot="; nocase; reference:cve,CVE-2007-2597; reference:url,www.milw0rm.com/exploits/3885; reference:url,doc.emergingthreats.net/2003867; classtype:web-application-attack; sid:2003867; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TellTarget CMS Remote Inclusion 3_lay.php tt_docroot** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2597|url,www.milw0rm.com/exploits/3885|url,doc.emergingthreats.net/2003867

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ThWboard SQL Injection Attempt -- index.php board SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"board["; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-0340; reference:url,www.milw0rm.com/exploits/3124; reference:url,doc.emergingthreats.net/2005567; classtype:web-application-attack; sid:2005567; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005567
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ThWboard SQL Injection Attempt -- index.php board SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"board["; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-0340; reference:url,www.milw0rm.com/exploits/3124; reference:url,doc.emergingthreats.net/2005567; classtype:web-application-attack; sid:2005567; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ThWboard SQL Injection Attempt -- index.php board SELECT** 

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

URL reference : cve,CVE-2007-0340|url,www.milw0rm.com/exploits/3124|url,doc.emergingthreats.net/2005567

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ThWboard SQL Injection Attempt -- index.php board UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"board["; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-0340; reference:url,www.milw0rm.com/exploits/3124; reference:url,doc.emergingthreats.net/2005568; classtype:web-application-attack; sid:2005568; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005568
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ThWboard SQL Injection Attempt -- index.php board UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"board["; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-0340; reference:url,www.milw0rm.com/exploits/3124; reference:url,doc.emergingthreats.net/2005568; classtype:web-application-attack; sid:2005568; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ThWboard SQL Injection Attempt -- index.php board UNION SELECT** 

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

URL reference : cve,CVE-2007-0340|url,www.milw0rm.com/exploits/3124|url,doc.emergingthreats.net/2005568

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ThWboard SQL Injection Attempt -- index.php board INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"board["; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-0340; reference:url,www.milw0rm.com/exploits/3124; reference:url,doc.emergingthreats.net/2005569; classtype:web-application-attack; sid:2005569; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005569
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ThWboard SQL Injection Attempt -- index.php board INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"board["; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-0340; reference:url,www.milw0rm.com/exploits/3124; reference:url,doc.emergingthreats.net/2005569; classtype:web-application-attack; sid:2005569; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ThWboard SQL Injection Attempt -- index.php board INSERT** 

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

URL reference : cve,CVE-2007-0340|url,www.milw0rm.com/exploits/3124|url,doc.emergingthreats.net/2005569

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ThWboard SQL Injection Attempt -- index.php board ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"board["; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-0340; reference:url,www.milw0rm.com/exploits/3124; reference:url,doc.emergingthreats.net/2005571; classtype:web-application-attack; sid:2005571; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005571
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ThWboard SQL Injection Attempt -- index.php board ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"board["; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-0340; reference:url,www.milw0rm.com/exploits/3124; reference:url,doc.emergingthreats.net/2005571; classtype:web-application-attack; sid:2005571; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ThWboard SQL Injection Attempt -- index.php board ASCII** 

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

URL reference : cve,CVE-2007-0340|url,www.milw0rm.com/exploits/3124|url,doc.emergingthreats.net/2005571

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ThWboard SQL Injection Attempt -- index.php board UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"board["; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-0340; reference:url,www.milw0rm.com/exploits/3124; reference:url,doc.emergingthreats.net/2005572; classtype:web-application-attack; sid:2005572; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2005572
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS ThWboard SQL Injection Attempt -- index.php board UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"board["; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-0340; reference:url,www.milw0rm.com/exploits/3124; reference:url,doc.emergingthreats.net/2005572; classtype:web-application-attack; sid:2005572; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **ThWboard SQL Injection Attempt -- index.php board UPDATE** 

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

URL reference : cve,CVE-2007-0340|url,www.milw0rm.com/exploits/3124|url,doc.emergingthreats.net/2005572

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Apache Tomcat XSS Attempt -- implicit-objects.jsp"; flow:established,to_server; uricontent:"/implicit-objects.jsp?"; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2006-7195; reference:url,www.frsirt.com/english/advisories/2007/1729; reference:url,doc.emergingthreats.net/2003902; classtype:web-application-attack; sid:2003902; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003902
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Apache Tomcat XSS Attempt -- implicit-objects.jsp"; flow:established,to_server; uricontent:"/implicit-objects.jsp?"; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2006-7195; reference:url,www.frsirt.com/english/advisories/2007/1729; reference:url,doc.emergingthreats.net/2003902; classtype:web-application-attack; sid:2003902; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Apache Tomcat XSS Attempt -- implicit-objects.jsp** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2006-7195|url,www.frsirt.com/english/advisories/2007/1729|url,doc.emergingthreats.net/2003902

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Tomcat XSS Attempt -- hello.jsp test"; flow:established,to_server; uricontent:"/appdev/sample/web/hello.jsp?"; nocase; uricontent:"test="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-1355; reference:url,www.securityfocus.com/bid/24058; reference:url,doc.emergingthreats.net/2004575; classtype:web-application-attack; sid:2004575; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004575
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Tomcat XSS Attempt -- hello.jsp test"; flow:established,to_server; uricontent:"/appdev/sample/web/hello.jsp?"; nocase; uricontent:"test="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-1355; reference:url,www.securityfocus.com/bid/24058; reference:url,doc.emergingthreats.net/2004575; classtype:web-application-attack; sid:2004575; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Tomcat XSS Attempt -- hello.jsp test** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-1355|url,www.securityfocus.com/bid/24058|url,doc.emergingthreats.net/2004575

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TopTree Remote Inclusion Attempt -- tpl_message.php right_file"; flow:established,to_server; uricontent:"/templates/default/tpl_message.php?"; nocase; uricontent:"right_file="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2544; reference:url,www.milw0rm.com/exploits/3854; reference:url,doc.emergingthreats.net/2003669; classtype:web-application-attack; sid:2003669; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003669
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TopTree Remote Inclusion Attempt -- tpl_message.php right_file"; flow:established,to_server; uricontent:"/templates/default/tpl_message.php?"; nocase; uricontent:"right_file="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2544; reference:url,www.milw0rm.com/exploits/3854; reference:url,doc.emergingthreats.net/2003669; classtype:web-application-attack; sid:2003669; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TopTree Remote Inclusion Attempt -- tpl_message.php right_file** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2544|url,www.milw0rm.com/exploits/3854|url,doc.emergingthreats.net/2003669

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TotalCalendar config.php inc_dir Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/config.php?"; nocase; uricontent:"inc_dir="; nocase; pcre:"/inc_dir=\s*(https?|ftps?|php)\:\//Ui"; reference:bugtraq,34617; reference:url,milw0rm.com/exploits/8494; reference:url,doc.emergingthreats.net/2009663; classtype:web-application-attack; sid:2009663; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009663
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TotalCalendar config.php inc_dir Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/config.php?"; nocase; uricontent:"inc_dir="; nocase; pcre:"/inc_dir=\s*(https?|ftps?|php)\:\//Ui"; reference:bugtraq,34617; reference:url,milw0rm.com/exploits/8494; reference:url,doc.emergingthreats.net/2009663; classtype:web-application-attack; sid:2009663; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TotalCalendar config.php inc_dir Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,34617|url,milw0rm.com/exploits/8494|url,doc.emergingthreats.net/2009663

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Track+ XSS Attempt -- reportItem.do projId"; flow:established,to_server; uricontent:"/reportItem.do?"; nocase; uricontent:"projId="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-2819; reference:url,www.securityfocus.com/bid/24060; reference:url,doc.emergingthreats.net/2004558; classtype:web-application-attack; sid:2004558; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004558
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Track+ XSS Attempt -- reportItem.do projId"; flow:established,to_server; uricontent:"/reportItem.do?"; nocase; uricontent:"projId="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-2819; reference:url,www.securityfocus.com/bid/24060; reference:url,doc.emergingthreats.net/2004558; classtype:web-application-attack; sid:2004558; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Track+ XSS Attempt -- reportItem.do projId** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2819|url,www.securityfocus.com/bid/24060|url,doc.emergingthreats.net/2004558

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Tropicalm Remote Inclusion Attempt -- dosearch.php RESPATH"; flow:established,to_server; uricontent:"/dosearch.php?"; nocase; uricontent:"RESPATH="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2530; reference:url,www.milw0rm.com/exploits/3865; reference:url,doc.emergingthreats.net/2003678; classtype:web-application-attack; sid:2003678; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003678
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Tropicalm Remote Inclusion Attempt -- dosearch.php RESPATH"; flow:established,to_server; uricontent:"/dosearch.php?"; nocase; uricontent:"RESPATH="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2530; reference:url,www.milw0rm.com/exploits/3865; reference:url,doc.emergingthreats.net/2003678; classtype:web-application-attack; sid:2003678; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Tropicalm Remote Inclusion Attempt -- dosearch.php RESPATH** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2530|url,www.milw0rm.com/exploits/3865|url,doc.emergingthreats.net/2003678

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Turnkey Arcade Script id parameter SQL injection"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/index.php?"; nocase; uricontent:"action=play"; nocase; uricontent:"id="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/UNION.+SELECT/Ui"; reference:url,secunia.com/advisories/32890/; reference:url,milw0rm.com/exploits/7256; reference:url,doc.emergingthreats.net/2008934; classtype:web-application-attack; sid:2008934; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2008934
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Turnkey Arcade Script id parameter SQL injection"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/index.php?"; nocase; uricontent:"action=play"; nocase; uricontent:"id="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/UNION.+SELECT/Ui"; reference:url,secunia.com/advisories/32890/; reference:url,milw0rm.com/exploits/7256; reference:url,doc.emergingthreats.net/2008934; classtype:web-application-attack; sid:2008934; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Turnkey Arcade Script id parameter SQL injection** 

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

URL reference : url,secunia.com/advisories/32890/|url,milw0rm.com/exploits/7256|url,doc.emergingthreats.net/2008934

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TurnKeyWebTools Remote Inclusion Attempt -- payflow_pro.php abs_path"; flow:established,to_server; uricontent:"/include/payment/payflow_pro.php?"; nocase; uricontent:"abs_path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2474; reference:url,www.securityfocus.com/bid/23662; reference:url,doc.emergingthreats.net/2003687; classtype:web-application-attack; sid:2003687; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003687
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TurnKeyWebTools Remote Inclusion Attempt -- payflow_pro.php abs_path"; flow:established,to_server; uricontent:"/include/payment/payflow_pro.php?"; nocase; uricontent:"abs_path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2474; reference:url,www.securityfocus.com/bid/23662; reference:url,doc.emergingthreats.net/2003687; classtype:web-application-attack; sid:2003687; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TurnKeyWebTools Remote Inclusion Attempt -- payflow_pro.php abs_path** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2474|url,www.securityfocus.com/bid/23662|url,doc.emergingthreats.net/2003687

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TurnKeyWebTools Remote Inclusion Attempt -- global.php abs_path"; flow:established,to_server; uricontent:"/global.php?"; nocase; uricontent:"abs_path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2474; reference:url,www.securityfocus.com/bid/23662; reference:url,doc.emergingthreats.net/2003688; classtype:web-application-attack; sid:2003688; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003688
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TurnKeyWebTools Remote Inclusion Attempt -- global.php abs_path"; flow:established,to_server; uricontent:"/global.php?"; nocase; uricontent:"abs_path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2474; reference:url,www.securityfocus.com/bid/23662; reference:url,doc.emergingthreats.net/2003688; classtype:web-application-attack; sid:2003688; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TurnKeyWebTools Remote Inclusion Attempt -- global.php abs_path** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2474|url,www.securityfocus.com/bid/23662|url,doc.emergingthreats.net/2003688

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TurnKeyWebTools Remote Inclusion Attempt -- libsecure.php abs_path"; flow:established,to_server; uricontent:"/libsecure.php?"; nocase; uricontent:"abs_path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2474; reference:url,www.securityfocus.com/bid/23662; reference:url,doc.emergingthreats.net/2003689; classtype:web-application-attack; sid:2003689; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003689
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TurnKeyWebTools Remote Inclusion Attempt -- libsecure.php abs_path"; flow:established,to_server; uricontent:"/libsecure.php?"; nocase; uricontent:"abs_path="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2474; reference:url,www.securityfocus.com/bid/23662; reference:url,doc.emergingthreats.net/2003689; classtype:web-application-attack; sid:2003689; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TurnKeyWebTools Remote Inclusion Attempt -- libsecure.php abs_path** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2474|url,www.securityfocus.com/bid/23662|url,doc.emergingthreats.net/2003689

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TurnkeyWebTools SunShop Shopping Cart XSS Attempt -- index.php l"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"l="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2547; reference:url,www.securityfocus.com/bid/23856; reference:url,doc.emergingthreats.net/2003917; classtype:web-application-attack; sid:2003917; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003917
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TurnkeyWebTools SunShop Shopping Cart XSS Attempt -- index.php l"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"l="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2547; reference:url,www.securityfocus.com/bid/23856; reference:url,doc.emergingthreats.net/2003917; classtype:web-application-attack; sid:2003917; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TurnkeyWebTools SunShop Shopping Cart XSS Attempt -- index.php l** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2547|url,www.securityfocus.com/bid/23856|url,doc.emergingthreats.net/2003917

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- browseCat.php catFile"; flow:established,to_server; uricontent:"/browseCat.php?"; nocase; uricontent:"catFile="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003888; classtype:web-application-attack; sid:2003888; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003888
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- browseCat.php catFile"; flow:established,to_server; uricontent:"/browseCat.php?"; nocase; uricontent:"catFile="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003888; classtype:web-application-attack; sid:2003888; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TutorialCMS (Photoshop Tutorials) XSS Attempt -- browseCat.php catFile** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2600|url,www.milw0rm.com/exploits/3887|url,doc.emergingthreats.net/2003888

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- browseSubCat.php catFile"; flow:established,to_server; uricontent:"/browseSubCat.php?"; nocase; uricontent:"catFile="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003889; classtype:web-application-attack; sid:2003889; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003889
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- browseSubCat.php catFile"; flow:established,to_server; uricontent:"/browseSubCat.php?"; nocase; uricontent:"catFile="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003889; classtype:web-application-attack; sid:2003889; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TutorialCMS (Photoshop Tutorials) XSS Attempt -- browseSubCat.php catFile** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2600|url,www.milw0rm.com/exploits/3887|url,doc.emergingthreats.net/2003889

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- openTutorial.php id"; flow:established,to_server; uricontent:"/openTutorial.php?"; nocase; uricontent:"id="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003890; classtype:web-application-attack; sid:2003890; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003890
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- openTutorial.php id"; flow:established,to_server; uricontent:"/openTutorial.php?"; nocase; uricontent:"id="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003890; classtype:web-application-attack; sid:2003890; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TutorialCMS (Photoshop Tutorials) XSS Attempt -- openTutorial.php id** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2600|url,www.milw0rm.com/exploits/3887|url,doc.emergingthreats.net/2003890

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- topFrame.php id"; flow:established,to_server; uricontent:"/topFrame.php?"; nocase; uricontent:"id="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003891; classtype:web-application-attack; sid:2003891; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003891
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- topFrame.php id"; flow:established,to_server; uricontent:"/topFrame.php?"; nocase; uricontent:"id="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003891; classtype:web-application-attack; sid:2003891; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TutorialCMS (Photoshop Tutorials) XSS Attempt -- topFrame.php id** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2600|url,www.milw0rm.com/exploits/3887|url,doc.emergingthreats.net/2003891

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- editListing.php id"; flow:established,to_server; uricontent:"/admin/editListing.php?"; nocase; uricontent:"id="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003892; classtype:web-application-attack; sid:2003892; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003892
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- editListing.php id"; flow:established,to_server; uricontent:"/admin/editListing.php?"; nocase; uricontent:"id="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003892; classtype:web-application-attack; sid:2003892; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TutorialCMS (Photoshop Tutorials) XSS Attempt -- editListing.php id** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2600|url,www.milw0rm.com/exploits/3887|url,doc.emergingthreats.net/2003892

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- search.php search"; flow:established,to_server; uricontent:"/search.php?"; nocase; uricontent:"search="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003893; classtype:web-application-attack; sid:2003893; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003893
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TutorialCMS (Photoshop Tutorials) XSS Attempt -- search.php search"; flow:established,to_server; uricontent:"/search.php?"; nocase; uricontent:"search="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2600; reference:url,www.milw0rm.com/exploits/3887; reference:url,doc.emergingthreats.net/2003893; classtype:web-application-attack; sid:2003893; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TutorialCMS (Photoshop Tutorials) XSS Attempt -- search.php search** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2600|url,www.milw0rm.com/exploits/3887|url,doc.emergingthreats.net/2003893

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TWiki INCLUDE remote command execution attempt"; flow:to_server,established; uricontent:"INCLUDE"; nocase; pcre:"/%INCLUDE\s*{.*rev=\"\d+\|.+\".*}\s*%/i"; reference:bugtraq,14960; reference:url,doc.emergingthreats.net/2002662; classtype:web-application-attack; sid:2002662; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002662
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS TWiki INCLUDE remote command execution attempt"; flow:to_server,established; uricontent:"INCLUDE"; nocase; pcre:"/%INCLUDE\s*{.*rev=\"\d+\|.+\".*}\s*%/i"; reference:bugtraq,14960; reference:url,doc.emergingthreats.net/2002662; classtype:web-application-attack; sid:2002662; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **TWiki INCLUDE remote command execution attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,14960|url,doc.emergingthreats.net/2002662

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 7

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Ultrastats serverid parameter SQL Injection"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/index.php?"; nocase; uricontent:"serverid="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/UNION.+SELECT/Ui"; reference:bugtraq,32340; reference:url,milw0rm.com/exploits/7148; reference:url,doc.emergingthreats.net/2008872; classtype:web-application-attack; sid:2008872; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2008872
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Ultrastats serverid parameter SQL Injection"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/index.php?"; nocase; uricontent:"serverid="; nocase; uricontent:"UNION"; nocase; uricontent:"SELECT"; nocase; pcre:"/UNION.+SELECT/Ui"; reference:bugtraq,32340; reference:url,milw0rm.com/exploits/7148; reference:url,doc.emergingthreats.net/2008872; classtype:web-application-attack; sid:2008872; rev:3; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Ultrastats serverid parameter SQL Injection** 

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

URL reference : bugtraq,32340|url,milw0rm.com/exploits/7148|url,doc.emergingthreats.net/2008872

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Ultrize TimeSheet timesheet.php include_dir Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/include/timesheet.php?"; nocase; uricontent:"config[include_dir]="; pcre:"/config\[include_dir\]=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/9297; reference:url,secunia.com/advisories/36033/; reference:url,doc.emergingthreats.net/2010126; classtype:web-application-attack; sid:2010126; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010126
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Ultrize TimeSheet timesheet.php include_dir Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/include/timesheet.php?"; nocase; uricontent:"config[include_dir]="; pcre:"/config\[include_dir\]=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/9297; reference:url,secunia.com/advisories/36033/; reference:url,doc.emergingthreats.net/2010126; classtype:web-application-attack; sid:2010126; rev:2; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Ultrize TimeSheet timesheet.php include_dir Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/9297|url,secunia.com/advisories/36033/|url,doc.emergingthreats.net/2010126

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 2

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS VM Watermark Remote Inclusion Attempt -- watermark.php GALLERY_BASEDIR"; flow:established,to_server; uricontent:"/watermark.php?"; nocase; uricontent:"GALLERY_BASEDIR="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2575; reference:url,www.milw0rm.com/exploits/3857; reference:url,doc.emergingthreats.net/2003692; classtype:web-application-attack; sid:2003692; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003692
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS VM Watermark Remote Inclusion Attempt -- watermark.php GALLERY_BASEDIR"; flow:established,to_server; uricontent:"/watermark.php?"; nocase; uricontent:"GALLERY_BASEDIR="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2575; reference:url,www.milw0rm.com/exploits/3857; reference:url,doc.emergingthreats.net/2003692; classtype:web-application-attack; sid:2003692; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **VM Watermark Remote Inclusion Attempt -- watermark.php GALLERY_BASEDIR** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2575|url,www.milw0rm.com/exploits/3857|url,doc.emergingthreats.net/2003692

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS VP-ASP Shopping Cart XSS Attempt -- shopcontent.asp type"; flow:established,to_server; uricontent:"/shopcontent.asp?"; nocase; uricontent:"type="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-2790; reference:url,www.securityfocus.com/archive/1/archive/1/468834/100/0/threaded; reference:url,doc.emergingthreats.net/2004573; classtype:web-application-attack; sid:2004573; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004573
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS VP-ASP Shopping Cart XSS Attempt -- shopcontent.asp type"; flow:established,to_server; uricontent:"/shopcontent.asp?"; nocase; uricontent:"type="; nocase; uricontent:"script"; nocase; pcre:"/.*<?(java|vb)?script>?.*<.+\/script>?/iU"; reference:cve,CVE-2007-2790; reference:url,www.securityfocus.com/archive/1/archive/1/468834/100/0/threaded; reference:url,doc.emergingthreats.net/2004573; classtype:web-application-attack; sid:2004573; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **VP-ASP Shopping Cart XSS Attempt -- shopcontent.asp type** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2790|url,www.securityfocus.com/archive/1/archive/1/468834/100/0/threaded|url,doc.emergingthreats.net/2004573

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHP VWar Remote File Inclusion get_header.php"; flow:established,to_server; uricontent:"/get_header.php"; nocase; pcre:"/vwar_root=\s*(ftps?|https?|php)\:\//Ui"; reference:url,www.milw0rm.com/exploits/1632; reference:cve,2006-1636; reference:bugtraq,17358; reference:url,doc.emergingthreats.net/2002899; classtype:web-application-attack; sid:2002899; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002899
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHP VWar Remote File Inclusion get_header.php"; flow:established,to_server; uricontent:"/get_header.php"; nocase; pcre:"/vwar_root=\s*(ftps?|https?|php)\:\//Ui"; reference:url,www.milw0rm.com/exploits/1632; reference:cve,2006-1636; reference:bugtraq,17358; reference:url,doc.emergingthreats.net/2002899; classtype:web-application-attack; sid:2002899; rev:7; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHP VWar Remote File Inclusion get_header.php** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,www.milw0rm.com/exploits/1632|cve,2006-1636|bugtraq,17358|url,doc.emergingthreats.net/2002899

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 7

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHP VWar Remote File Inclusion functions_install.php"; flow:established,to_server; uricontent:"/functions_install.php"; nocase; pcre:"/vwar_root=\s*(ftps?|https?|php)\:\//Ui"; reference:cve,2006-1503; reference:bugtraq,17290; reference:url,doc.emergingthreats.net/2002902; classtype:web-application-attack; sid:2002902; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2002902
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS PHP VWar Remote File Inclusion functions_install.php"; flow:established,to_server; uricontent:"/functions_install.php"; nocase; pcre:"/vwar_root=\s*(ftps?|https?|php)\:\//Ui"; reference:cve,2006-1503; reference:bugtraq,17290; reference:url,doc.emergingthreats.net/2002902; classtype:web-application-attack; sid:2002902; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **PHP VWar Remote File Inclusion functions_install.php** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,2006-1503|bugtraq,17290|url,doc.emergingthreats.net/2002902

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Versado CMS Remote Inclusion Attempt -- ajax_listado.php urlModulo"; flow:established,to_server; uricontent:"/includes/ajax_listado.php?"; nocase; uricontent:"urlModulo="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2541; reference:url,www.milw0rm.com/exploits/3847; reference:url,doc.emergingthreats.net/2003671; classtype:web-application-attack; sid:2003671; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003671
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Versado CMS Remote Inclusion Attempt -- ajax_listado.php urlModulo"; flow:established,to_server; uricontent:"/includes/ajax_listado.php?"; nocase; uricontent:"urlModulo="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2541; reference:url,www.milw0rm.com/exploits/3847; reference:url,doc.emergingthreats.net/2003671; classtype:web-application-attack; sid:2003671; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Versado CMS Remote Inclusion Attempt -- ajax_listado.php urlModulo** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2541|url,www.milw0rm.com/exploits/3847|url,doc.emergingthreats.net/2003671

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 10000 (msg:"ET WEB_SPECIFIC_APPS Virtualmin left.cgi XSS attempt "; flow:to_server,established; content:"GET "; depth:4; content:"/left.cgi?"; nocase; content:"dom="; nocase; content:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/i"; reference:url,milw0rm.com/exploits/9143; reference:url,doc.emergingthreats.net/2009587; classtype:web-application-attack; sid:2009587; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009587
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 10000 (msg:"ET WEB_SPECIFIC_APPS Virtualmin left.cgi XSS attempt "; flow:to_server,established; content:"GET "; depth:4; content:"/left.cgi?"; nocase; content:"dom="; nocase; content:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/i"; reference:url,milw0rm.com/exploits/9143; reference:url,doc.emergingthreats.net/2009587; classtype:web-application-attack; sid:2009587; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Virtualmin left.cgi XSS attempt ** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/9143|url,doc.emergingthreats.net/2009587

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 10000 (msg:"ET WEB_SPECIFIC_APPS Virtualmin link.cgi XSS attempt "; flow:to_server,established; content:"GET "; depth:4; content:"/link.cgi/"; nocase; content:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:url,milw0rm.com/exploits/9143; reference:url,doc.emergingthreats.net/2009588; classtype:web-application-attack; sid:2009588; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009588
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 10000 (msg:"ET WEB_SPECIFIC_APPS Virtualmin link.cgi XSS attempt "; flow:to_server,established; content:"GET "; depth:4; content:"/link.cgi/"; nocase; content:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:url,milw0rm.com/exploits/9143; reference:url,doc.emergingthreats.net/2009588; classtype:web-application-attack; sid:2009588; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Virtualmin link.cgi XSS attempt ** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/9143|url,doc.emergingthreats.net/2009588

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 10000 (msg:"ET WEB_SPECIFIC_APPS Virtualmin Anonymous Proxy attempt"; flow:to_server,established; content:"GET "; depth:4; content:"/virtual-server/link.cgi/"; nocase; content:"/http\://"; nocase; reference:url,milw0rm.com/exploits/9143; reference:url,doc.emergingthreats.net/2009589; classtype:web-application-attack; sid:2009589; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

# 2009589
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 10000 (msg:"ET WEB_SPECIFIC_APPS Virtualmin Anonymous Proxy attempt"; flow:to_server,established; content:"GET "; depth:4; content:"/virtual-server/link.cgi/"; nocase; content:"/http\://"; nocase; reference:url,milw0rm.com/exploits/9143; reference:url,doc.emergingthreats.net/2009589; classtype:web-application-attack; sid:2009589; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **Virtualmin Anonymous Proxy attempt** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/9143|url,doc.emergingthreats.net/2009589

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS VirtueMart Google Base Component admin.googlebase.php Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/admin.googlebase.php?"; nocase; uricontent:"mosConfig_absolute_path="; nocase; pcre:"/mosConfig_absolute_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32098; reference:url,milw0rm.com/exploits/6975; reference:url,doc.emergingthreats.net/2009877; classtype:web-application-attack; sid:2009877; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009877
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS VirtueMart Google Base Component admin.googlebase.php Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/admin.googlebase.php?"; nocase; uricontent:"mosConfig_absolute_path="; nocase; pcre:"/mosConfig_absolute_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32098; reference:url,milw0rm.com/exploits/6975; reference:url,doc.emergingthreats.net/2009877; classtype:web-application-attack; sid:2009877; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **VirtueMart Google Base Component admin.googlebase.php Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32098|url,milw0rm.com/exploits/6975|url,doc.emergingthreats.net/2009877

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id SELECT"; flow:established,to_server; uricontent:"/default.asp?"; nocase; uricontent:"id="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2803; reference:url,www.secunia.com/advisories/25348; reference:url,doc.emergingthreats.net/2003993; classtype:web-application-attack; sid:2003993; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003993
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id SELECT"; flow:established,to_server; uricontent:"/default.asp?"; nocase; uricontent:"id="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+SELECT.+FROM/Ui"; reference:cve,CVE-2007-2803; reference:url,www.secunia.com/advisories/25348; reference:url,doc.emergingthreats.net/2003993; classtype:web-application-attack; sid:2003993; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id SELECT** 

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

URL reference : cve,CVE-2007-2803|url,www.secunia.com/advisories/25348|url,doc.emergingthreats.net/2003993

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id UNION SELECT"; flow:established,to_server; uricontent:"/default.asp?"; nocase; uricontent:"id="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2803; reference:url,www.secunia.com/advisories/25348; reference:url,doc.emergingthreats.net/2003994; classtype:web-application-attack; sid:2003994; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003994
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id UNION SELECT"; flow:established,to_server; uricontent:"/default.asp?"; nocase; uricontent:"id="; nocase; uricontent:"UNION"; nocase; pcre:"/.+UNION\s+SELECT/Ui"; reference:cve,CVE-2007-2803; reference:url,www.secunia.com/advisories/25348; reference:url,doc.emergingthreats.net/2003994; classtype:web-application-attack; sid:2003994; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id UNION SELECT** 

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

URL reference : cve,CVE-2007-2803|url,www.secunia.com/advisories/25348|url,doc.emergingthreats.net/2003994

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id INSERT"; flow:established,to_server; uricontent:"/default.asp?"; nocase; uricontent:"id="; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2803; reference:url,www.secunia.com/advisories/25348; reference:url,doc.emergingthreats.net/2003995; classtype:web-application-attack; sid:2003995; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003995
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id INSERT"; flow:established,to_server; uricontent:"/default.asp?"; nocase; uricontent:"id="; nocase; uricontent:"INSERT"; nocase; pcre:"/.+INSERT.+INTO/Ui"; reference:cve,CVE-2007-2803; reference:url,www.secunia.com/advisories/25348; reference:url,doc.emergingthreats.net/2003995; classtype:web-application-attack; sid:2003995; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id INSERT** 

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

URL reference : cve,CVE-2007-2803|url,www.secunia.com/advisories/25348|url,doc.emergingthreats.net/2003995

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id DELETE"; flow:established,to_server; uricontent:"/default.asp?"; nocase; uricontent:"id="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2803; reference:url,www.secunia.com/advisories/25348; reference:url,doc.emergingthreats.net/2003996; classtype:web-application-attack; sid:2003996; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003996
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id DELETE"; flow:established,to_server; uricontent:"/default.asp?"; nocase; uricontent:"id="; nocase; uricontent:"DELETE"; nocase; pcre:"/.+DELETE.+FROM/Ui"; reference:cve,CVE-2007-2803; reference:url,www.secunia.com/advisories/25348; reference:url,doc.emergingthreats.net/2003996; classtype:web-application-attack; sid:2003996; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id DELETE** 

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

URL reference : cve,CVE-2007-2803|url,www.secunia.com/advisories/25348|url,doc.emergingthreats.net/2003996

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id ASCII"; flow:established,to_server; uricontent:"/default.asp?"; nocase; uricontent:"id="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2803; reference:url,www.secunia.com/advisories/25348; reference:url,doc.emergingthreats.net/2003997; classtype:web-application-attack; sid:2003997; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003997
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id ASCII"; flow:established,to_server; uricontent:"/default.asp?"; nocase; uricontent:"id="; nocase; uricontent:"SELECT"; nocase; pcre:"/.+ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-2803; reference:url,www.secunia.com/advisories/25348; reference:url,doc.emergingthreats.net/2003997; classtype:web-application-attack; sid:2003997; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Vizayn Urun Tanitim Sitesi SQL Injection Attempt -- default.asp id ASCII** 

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

URL reference : cve,CVE-2007-2803|url,www.secunia.com/advisories/25348|url,doc.emergingthreats.net/2003997

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Way Of The Warrior crea.php plancia Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"crea.php?"; nocase; uricontent:"plancia="; nocase; pcre:"/plancia=\s*(ftps?|https?|php)\:\//Ui"; reference:url,secunia.com/advisories/32515/; reference:url,milw0rm.com/exploits/6992; reference:url,doc.emergingthreats.net/2008826; classtype:web-application-attack; sid:2008826; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2008826
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Way Of The Warrior crea.php plancia Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"crea.php?"; nocase; uricontent:"plancia="; nocase; pcre:"/plancia=\s*(ftps?|https?|php)\:\//Ui"; reference:url,secunia.com/advisories/32515/; reference:url,milw0rm.com/exploits/6992; reference:url,doc.emergingthreats.net/2008826; classtype:web-application-attack; sid:2008826; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Way Of The Warrior crea.php plancia Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,secunia.com/advisories/32515/|url,milw0rm.com/exploits/6992|url,doc.emergingthreats.net/2008826

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WeBid cron.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/cron.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8195; reference:bugtraq,34074; reference:url,doc.emergingthreats.net/2009307; classtype:web-application-attack; sid:2009307; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009307
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WeBid cron.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/cron.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8195; reference:bugtraq,34074; reference:url,doc.emergingthreats.net/2009307; classtype:web-application-attack; sid:2009307; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WeBid cron.php include_path Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/8195|bugtraq,34074|url,doc.emergingthreats.net/2009307

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WeBid ST_browsers.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/ST_browsers.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8195; reference:bugtraq,34074; reference:url,doc.emergingthreats.net/2009309; classtype:web-application-attack; sid:2009309; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009309
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WeBid ST_browsers.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/ST_browsers.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8195; reference:bugtraq,34074; reference:url,doc.emergingthreats.net/2009309; classtype:web-application-attack; sid:2009309; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WeBid ST_browsers.php include_path Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/8195|bugtraq,34074|url,doc.emergingthreats.net/2009309

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WeBid ST_countries.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/ST_countries.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8195; reference:bugtraq,34074; reference:url,doc.emergingthreats.net/2009311; classtype:web-application-attack; sid:2009311; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009311
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WeBid ST_countries.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/ST_countries.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8195; reference:bugtraq,34074; reference:url,doc.emergingthreats.net/2009311; classtype:web-application-attack; sid:2009311; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WeBid ST_countries.php include_path Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/8195|bugtraq,34074|url,doc.emergingthreats.net/2009311

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WeBid ST_platforms.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/ST_platforms.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8195; reference:bugtraq,34074; reference:url,doc.emergingthreats.net/2009313; classtype:web-application-attack; sid:2009313; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2009313
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WeBid ST_platforms.php include_path Parameter Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/ST_platforms.php?"; nocase; uricontent:"include_path="; nocase; pcre:"/include_path=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8195; reference:bugtraq,34074; reference:url,doc.emergingthreats.net/2009313; classtype:web-application-attack; sid:2009313; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WeBid ST_platforms.php include_path Parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/8195|bugtraq,34074|url,doc.emergingthreats.net/2009313

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS webCalendar Remote File include"; flow: to_server,established; uricontent:"includedir="; pcre:"/\/ws\/(login|get_reminders|get_events)\.php/"; reference:url,www.securityfocus.com/archive/1/462957; reference:url,doc.emergingthreats.net/2003520; classtype:web-application-attack; sid:2003520; rev:8; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003520
`#alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS webCalendar Remote File include"; flow: to_server,established; uricontent:"includedir="; pcre:"/\/ws\/(login|get_reminders|get_events)\.php/"; reference:url,www.securityfocus.com/archive/1/462957; reference:url,doc.emergingthreats.net/2003520; classtype:web-application-attack; sid:2003520; rev:8; metadata:affected_product Any, attack_target Server, deployment Datacenter, tag Remote_File_Include, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **webCalendar Remote File include** 

Attack target : Server

Description : Remote File Include (RFI) is a technique used to exploit vulnerable "dynamic file include" mechanisms in web applications. When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked into including remote files with malicious code. File inclusion is typically used for packaging common code into separate files that are later referenced by main application modules. When a web application references an include file, the code in this file may be executed implicitly or explicitly by calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the web application might be vulnerable to RFI.

PHP is particularly vulnerable to file include attacks due to the extensive use of "file includes" in PHP and due to default server configurations that increase susceptibility to a file include attack. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

It is common for attackers to scan for LFI vulnerabilities against hundreds or thousands of servers and launch further, more sophisticated attacks should a server respond in a way that reveals it is vulnerable. You may see hundreds of these alerts in a short period of time indicating you are the target of a scanning campaign, all of which may be FPs. If you see a HTTP 200 response in the web server log files for the request generating the alert, you’ll want to investigate to determine if the attack was successful. Typically, after a successful attack, attackers will wget a trojan from a third party site and execute it, so that the attacker maintains control even if the vulnerable software is patched..

This rule classification is disabled by default, and can be enabled by people wanting to detect attacks against web applications.

Tags : Remote_File_Include

Affected products : Any

Alert Classtype : web-application-attack

URL reference : url,www.securityfocus.com/archive/1/462957|url,doc.emergingthreats.net/2003520

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 8

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Webmoney Advisor ActiveX Redirect Method Remote DoS Attempt"; flow:established,to_client; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"clsid"; nocase; content:"3AFFD7F7-FD3D-4C9D-8F83-03296A1A8840"; nocase; distance:0; content:"Redirect"; nocase; metadata: former_category WEB_SPECIFIC_APPS; reference:url,exploit-db.com/exploits/12431; reference:url,doc.emergingthreats.net/2011723; classtype:attempted-user; sid:2011723; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2010_07_30, updated_at 2019_04_15;)

# 2011723
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Webmoney Advisor ActiveX Redirect Method Remote DoS Attempt"; flow:established,to_client; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"clsid"; nocase; content:"3AFFD7F7-FD3D-4C9D-8F83-03296A1A8840"; nocase; distance:0; content:"Redirect"; nocase; metadata: former_category WEB_SPECIFIC_APPS; reference:url,exploit-db.com/exploits/12431; reference:url,doc.emergingthreats.net/2011723; classtype:attempted-user; sid:2011723; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2010_07_30, updated_at 2019_04_15;)
` 

Name : **Webmoney Advisor ActiveX Redirect Method Remote DoS Attempt** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,exploit-db.com/exploits/12431|url,doc.emergingthreats.net/2011723

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-04-15

Rev version : 2

Category : DELETED

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Webmoney Advisor ActiveX Control DoS Function Call"; flow:to_client,established; content:"ActiveXObject"; nocase; content:"TOOLBAR3Lib.ToolbarObj"; nocase; distance:0; content:"Redirect"; nocase; metadata: former_category WEB_SPECIFIC_APPS; reference:url,exploit-db.com/exploits/12431; reference:url,doc.emergingthreats.net/2011724; classtype:attempted-user; sid:2011724; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2010_07_30, updated_at 2019_04_15;)

# 2011724
`#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Webmoney Advisor ActiveX Control DoS Function Call"; flow:to_client,established; content:"ActiveXObject"; nocase; content:"TOOLBAR3Lib.ToolbarObj"; nocase; distance:0; content:"Redirect"; nocase; metadata: former_category WEB_SPECIFIC_APPS; reference:url,exploit-db.com/exploits/12431; reference:url,doc.emergingthreats.net/2011724; classtype:attempted-user; sid:2011724; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag ActiveX, signature_severity Major, created_at 2010_07_30, updated_at 2019_04_15;)
` 

Name : **Webmoney Advisor ActiveX Control DoS Function Call** 

Attack target : Client_Endpoint

Description : ActiveX controls are Microsoft Internet Explorer’s native version of plug-ins and can be leveraged by non browse applications as well..  ActiveX provides web application developers a facility to execute code on a client machine through the web browser.  Unfortunately, ActiveX controls have been a significant source of security problems both due to vulnerabilities in the ActiveX control itself, in the browser which can allow the activeX control to bypass security, as well as the fact that it has extensive capabilities to attacker drive code.
ActiveX controls are very powerful and can be used for legitimate and nefarious purposes including monitoring your personal browsing habits, install malware, generate pop-ups, log your keystrokes and passwords, and do other malicious things. ActiveX controls are actually not Internet Explorer-only. They also work in other Microsoft applications, such as Microsoft Office. Other browsers, such as Firefox, Chrome, Safari, and Opera, all use other types of browser plug-ins. ActiveX controls only function in Internet Explorer. A website that requires an ActiveX control is an Internet Explorer-only website.
If you see these ActiveX controls alerts firing, they are unlikely to succeed in exploiting all but legacy windows systems running older versions of IE.  To help validate whether the signature is triggering a valid compromise you should look for other malicious signatures related to the client endpoint which is triggering.  This includes Exploit Kit, Malware, and Command and Control signatures, along with looking to see if the web server is known to be malicious in ET Intelligence.

Tags : ActiveX

Affected products : Windows_XP/Vista/7/8/10/Server_32/64_Bit

Alert Classtype : attempted-user

URL reference : url,exploit-db.com/exploits/12431|url,doc.emergingthreats.net/2011724

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-04-15

Rev version : 2

Category : DELETED

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004754; classtype:web-application-attack; sid:2004754; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004754
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"SELECT"; nocase; pcre:"/SELECT.+FROM/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004754; classtype:web-application-attack; sid:2004754; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WebMplayer SQL Injection Attempt -- index.php strid SELECT** 

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

URL reference : cve,CVE-2007-1135|url,www.securityfocus.com/bid/22726|url,doc.emergingthreats.net/2004754

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004755; classtype:web-application-attack; sid:2004755; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004755
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid UNION SELECT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"UNION"; nocase; pcre:"/UNION\s+SELECT/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004755; classtype:web-application-attack; sid:2004755; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WebMplayer SQL Injection Attempt -- index.php strid UNION SELECT** 

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

URL reference : cve,CVE-2007-1135|url,www.securityfocus.com/bid/22726|url,doc.emergingthreats.net/2004755

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004756; classtype:web-application-attack; sid:2004756; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004756
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid INSERT"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"INSERT"; nocase; pcre:"/INSERT.+INTO/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004756; classtype:web-application-attack; sid:2004756; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WebMplayer SQL Injection Attempt -- index.php strid INSERT** 

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

URL reference : cve,CVE-2007-1135|url,www.securityfocus.com/bid/22726|url,doc.emergingthreats.net/2004756

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004757; classtype:web-application-attack; sid:2004757; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004757
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid DELETE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"DELETE"; nocase; pcre:"/DELETE.+FROM/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004757; classtype:web-application-attack; sid:2004757; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WebMplayer SQL Injection Attempt -- index.php strid DELETE** 

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

URL reference : cve,CVE-2007-1135|url,www.securityfocus.com/bid/22726|url,doc.emergingthreats.net/2004757

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004758; classtype:web-application-attack; sid:2004758; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004758
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid ASCII"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"SELECT"; nocase; pcre:"/ASCII\(.+SELECT/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004758; classtype:web-application-attack; sid:2004758; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WebMplayer SQL Injection Attempt -- index.php strid ASCII** 

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

URL reference : cve,CVE-2007-1135|url,www.securityfocus.com/bid/22726|url,doc.emergingthreats.net/2004758

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004759; classtype:web-application-attack; sid:2004759; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2004759
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WebMplayer SQL Injection Attempt -- index.php strid UPDATE"; flow:established,to_server; uricontent:"/index.php?"; nocase; uricontent:"strid="; nocase; uricontent:"UPDATE"; nocase; pcre:"/UPDATE.+SET/Ui"; reference:cve,CVE-2007-1135; reference:url,www.securityfocus.com/bid/22726; reference:url,doc.emergingthreats.net/2004759; classtype:web-application-attack; sid:2004759; rev:5; metadata:affected_product Web_Server_Applications, attack_target Web_Server, deployment Datacenter, tag SQL_Injection, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WebMplayer SQL Injection Attempt -- index.php strid UPDATE** 

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

URL reference : cve,CVE-2007-1135|url,www.securityfocus.com/bid/22726|url,doc.emergingthreats.net/2004759

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Webradev Download Protect EmailTemplates.class.php Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/Framework/EmailTemplates.class.php?"; nocase; uricontent:"GLOBALS[RootPath]="; nocase; pcre:"/GLOBALS\[RootPath\]=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8792; reference:url,doc.emergingthreats.net/2010092; classtype:web-application-attack; sid:2010092; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010092
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Webradev Download Protect EmailTemplates.class.php Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/Framework/EmailTemplates.class.php?"; nocase; uricontent:"GLOBALS[RootPath]="; nocase; pcre:"/GLOBALS\[RootPath\]=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8792; reference:url,doc.emergingthreats.net/2010092; classtype:web-application-attack; sid:2010092; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Webradev Download Protect EmailTemplates.class.php Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/8792|url,doc.emergingthreats.net/2010092

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Webradev Download Protect PDPEmailReplaceConstants.class.php Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/Customers/PDPEmailReplaceConstants.class.php?"; nocase; uricontent:"GLOBALS[RootPath]="; nocase; pcre:"/GLOBALS\[RootPath\]=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8792; reference:url,doc.emergingthreats.net/2010093; classtype:web-application-attack; sid:2010093; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010093
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Webradev Download Protect PDPEmailReplaceConstants.class.php Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/Customers/PDPEmailReplaceConstants.class.php?"; nocase; uricontent:"GLOBALS[RootPath]="; nocase; pcre:"/GLOBALS\[RootPath\]=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8792; reference:url,doc.emergingthreats.net/2010093; classtype:web-application-attack; sid:2010093; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Webradev Download Protect PDPEmailReplaceConstants.class.php Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/8792|url,doc.emergingthreats.net/2010093

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Webradev Download Protect ResellersManager.class.php Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/Admin/ResellersManager.class.php?"; nocase; uricontent:"GLOBALS[RootPath]="; nocase; pcre:"/GLOBALS\[RootPath\]=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8792; reference:url,doc.emergingthreats.net/2010094; classtype:web-application-attack; sid:2010094; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2010094
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Webradev Download Protect ResellersManager.class.php Remote File Inclusion"; flow:to_server,established; content:"GET "; depth:4; uricontent:"/Admin/ResellersManager.class.php?"; nocase; uricontent:"GLOBALS[RootPath]="; nocase; pcre:"/GLOBALS\[RootPath\]=\s*(https?|ftps?|php)\:\//Ui"; reference:url,milw0rm.com/exploits/8792; reference:url,doc.emergingthreats.net/2010094; classtype:web-application-attack; sid:2010094; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Webradev Download Protect ResellersManager.class.php Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : url,milw0rm.com/exploits/8792|url,doc.emergingthreats.net/2010094

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Werner Hilversum FAQ Manager header.php config_path parameter Remote File Inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/include/header.php?"; nocase; uricontent:"config_path="; nocase; pcre:"/config_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32472; reference:url,milw0rm.com/exploits/7229; reference:url,doc.emergingthreats.net/2008935; classtype:web-application-attack; sid:2008935; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2008935
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Werner Hilversum FAQ Manager header.php config_path parameter Remote File Inclusion"; flow:established,to_server; content:"GET "; depth:4; uricontent:"/include/header.php?"; nocase; uricontent:"config_path="; nocase; pcre:"/config_path=\s*(ftps?|https?|php)\:\//Ui"; reference:bugtraq,32472; reference:url,milw0rm.com/exploits/7229; reference:url,doc.emergingthreats.net/2008935; classtype:web-application-attack; sid:2008935; rev:3; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Werner Hilversum FAQ Manager header.php config_path parameter Remote File Inclusion** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : bugtraq,32472|url,milw0rm.com/exploits/7229|url,doc.emergingthreats.net/2008935

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 3

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Wikivi5 Remote Inclusion Attempt -- show.php sous_rep"; flow:established,to_server; uricontent:"/handlers/page/show.php?"; nocase; uricontent:"sous_rep="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2570; reference:url,www.milw0rm.com/exploits/3863; reference:url,doc.emergingthreats.net/2003696; classtype:web-application-attack; sid:2003696; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003696
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Wikivi5 Remote Inclusion Attempt -- show.php sous_rep"; flow:established,to_server; uricontent:"/handlers/page/show.php?"; nocase; uricontent:"sous_rep="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2570; reference:url,www.milw0rm.com/exploits/3863; reference:url,doc.emergingthreats.net/2003696; classtype:web-application-attack; sid:2003696; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Wikivi5 Remote Inclusion Attempt -- show.php sous_rep** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2570|url,www.milw0rm.com/exploits/3863|url,doc.emergingthreats.net/2003696

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WikkaWiki (Wikka Wiki) XSS Attempt -- usersettings.php name"; flow:established,to_server; uricontent:"/usersettings.php?"; nocase; uricontent:"name="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2551; reference:url,www.securityfocus.com/bid/23894; reference:url,doc.emergingthreats.net/2003916; classtype:web-application-attack; sid:2003916; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2003916
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WikkaWiki (Wikka Wiki) XSS Attempt -- usersettings.php name"; flow:established,to_server; uricontent:"/usersettings.php?"; nocase; uricontent:"name="; nocase; uricontent:"script"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2551; reference:url,www.securityfocus.com/bid/23894; reference:url,doc.emergingthreats.net/2003916; classtype:web-application-attack; sid:2003916; rev:5; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WikkaWiki (Wikka Wiki) XSS Attempt -- usersettings.php name** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2551|url,www.securityfocus.com/bid/23894|url,doc.emergingthreats.net/2003916

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 5

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WikyBlog XSS Attempt sessionRegister.php"; flow:established,to_server; uricontent:"/include/sessionRegister.php?"; nocase; uricontent:"| 3C |"; uricontent:"SCRIPT"; nocase; uricontent:"| 3E |"; reference:cve,CVE-2007-2781; reference:url,www.secunia.com/advisories/25308; reference:url,doc.emergingthreats.net/2004574; classtype:web-application-attack; sid:2004574; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)

# 2004574
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WikyBlog XSS Attempt sessionRegister.php"; flow:established,to_server; uricontent:"/include/sessionRegister.php?"; nocase; uricontent:"| 3C |"; uricontent:"SCRIPT"; nocase; uricontent:"| 3E |"; reference:cve,CVE-2007-2781; reference:url,www.secunia.com/advisories/25308; reference:url,doc.emergingthreats.net/2004574; classtype:web-application-attack; sid:2004574; rev:6; metadata:created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **WikyBlog XSS Attempt sessionRegister.php** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : web-application-attack

URL reference : cve,CVE-2007-2781|url,www.secunia.com/advisories/25308|url,doc.emergingthreats.net/2004574

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Wordpress wp-login.php redirect_to credentials stealing attempt"; flow:to_server,established; uricontent:"/wp-login.php"; nocase; uricontent:"redirect_to"; pcre:"/redirect_to=(ht|f)tps?\:\//iU"; reference:url,www.inliniac.net/blog/?p=71; reference:url,doc.emergingthreats.net/2003508; classtype:web-application-attack; sid:2003508; rev:6; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003508
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Wordpress wp-login.php redirect_to credentials stealing attempt"; flow:to_server,established; uricontent:"/wp-login.php"; nocase; uricontent:"redirect_to"; pcre:"/redirect_to=(ht|f)tps?\:\//iU"; reference:url,www.inliniac.net/blog/?p=71; reference:url,doc.emergingthreats.net/2003508; classtype:web-application-attack; sid:2003508; rev:6; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Wordpress wp-login.php redirect_to credentials stealing attempt** 

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

URL reference : url,www.inliniac.net/blog/?p=71|url,doc.emergingthreats.net/2003508

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Wordpress Remote Inclusion Attempt -- wptable-button.php wpPATH"; flow:established,to_server; uricontent:"/js/wptable-button.php?"; nocase; uricontent:"wpPATH="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2484; reference:url,www.milw0rm.com/exploits/3824; reference:url,doc.emergingthreats.net/2003685; classtype:web-application-attack; sid:2003685; rev:6; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003685
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Wordpress Remote Inclusion Attempt -- wptable-button.php wpPATH"; flow:established,to_server; uricontent:"/js/wptable-button.php?"; nocase; uricontent:"wpPATH="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2484; reference:url,www.milw0rm.com/exploits/3824; reference:url,doc.emergingthreats.net/2003685; classtype:web-application-attack; sid:2003685; rev:6; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Wordpress Remote Inclusion Attempt -- wptable-button.php wpPATH** 

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

URL reference : cve,CVE-2007-2484|url,www.milw0rm.com/exploits/3824|url,doc.emergingthreats.net/2003685

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Wordpress Remote Inclusion Attempt -- wordtube-button.php wpPATH"; flow:established,to_server; uricontent:"/wordtube-button.php?"; nocase; uricontent:"wpPATH="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2481; reference:url,www.milw0rm.com/exploits/3825; reference:url,doc.emergingthreats.net/2003686; classtype:web-application-attack; sid:2003686; rev:6; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

# 2003686
`#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS Wordpress Remote Inclusion Attempt -- wordtube-button.php wpPATH"; flow:established,to_server; uricontent:"/wordtube-button.php?"; nocase; uricontent:"wpPATH="; nocase; pcre:"/=\s*(https?|ftps?|php)\:\//Ui"; reference:cve,CVE-2007-2481; reference:url,www.milw0rm.com/exploits/3825; reference:url,doc.emergingthreats.net/2003686; classtype:web-application-attack; sid:2003686; rev:6; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)
` 

Name : **Wordpress Remote Inclusion Attempt -- wordtube-button.php wpPATH** 

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

URL reference : cve,CVE-2007-2481|url,www.milw0rm.com/exploits/3825|url,doc.emergingthreats.net/2003686

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2019-08-22

Rev version : 6

Category : WEB_SPECIFIC_APPS

Severity : Major

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SPECIFIC_APPS WordPress XSS Attempt -- sidebar.php"; flow:established,to_server; uricontent:"/sidebar.php?"; nocase; pcre:"/<?(java|vb)?script>?.*<.+\/script>?/Ui"; reference:cve,CVE-2007-2627; reference:url,www.securityfocus.com/archive/1/archive/1/467360/100/0/threaded; reference:url,doc.emergingthreats.net/2003885; classtype:web-application-attack; sid:2003885; rev:5; metadata:affected_product Wordpress, affected_product Wordpress_Plugins, attack_target Web_Server, deployment Datacenter, tag Wordpress, signature_severity Major, created_at 2010_07_30, updated_at 2019_08_22;)

