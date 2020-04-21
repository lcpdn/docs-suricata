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



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Address Mask Request"; icode:0; itype:17; classtype:misc-activity; sid:2100388; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100388
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Address Mask Request"; icode:0; itype:17; classtype:misc-activity; sid:2100388; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Address Mask Request** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Alternate Host Address"; icode:0; itype:6; classtype:misc-activity; sid:2100390; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100390
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Alternate Host Address"; icode:0; itype:6; classtype:misc-activity; sid:2100390; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Alternate Host Address** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Destination Host Unknown"; icode:7; itype:3; classtype:misc-activity; sid:2100394; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100394
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Destination Host Unknown"; icode:7; itype:3; classtype:misc-activity; sid:2100394; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Destination Host Unknown** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Destination Network Unknown"; icode:6; itype:3; classtype:misc-activity; sid:2100395; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100395
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Destination Network Unknown"; icode:6; itype:3; classtype:misc-activity; sid:2100395; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Destination Network Unknown** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Fragmentation Needed and DF bit was set"; icode:4; itype:3; classtype:misc-activity; sid:2100396; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100396
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Fragmentation Needed and DF bit was set"; icode:4; itype:3; classtype:misc-activity; sid:2100396; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Fragmentation Needed and DF bit was set** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Host Precedence Violation"; icode:14; itype:3; classtype:misc-activity; sid:2100397; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100397
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Host Precedence Violation"; icode:14; itype:3; classtype:misc-activity; sid:2100397; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Host Precedence Violation** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Host Unreachable for Type of Service"; icode:12; itype:3; classtype:misc-activity; sid:2100398; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100398
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Host Unreachable for Type of Service"; icode:12; itype:3; classtype:misc-activity; sid:2100398; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Host Unreachable for Type of Service** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Host Unreachable"; icode:1; itype:3; classtype:misc-activity; sid:2100399; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100399
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Host Unreachable"; icode:1; itype:3; classtype:misc-activity; sid:2100399; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Host Unreachable** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Network Unreachable for Type of Service"; icode:11; itype:3; classtype:misc-activity; sid:2100400; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100400
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Network Unreachable for Type of Service"; icode:11; itype:3; classtype:misc-activity; sid:2100400; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Network Unreachable for Type of Service** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Network Unreachable"; icode:0; itype:3; classtype:misc-activity; sid:2100401; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100401
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Network Unreachable"; icode:0; itype:3; classtype:misc-activity; sid:2100401; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Network Unreachable** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Port Unreachable"; icode:3; itype:3; classtype:misc-activity; sid:2100402; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100402
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Port Unreachable"; icode:3; itype:3; classtype:misc-activity; sid:2100402; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Port Unreachable** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Precedence Cutoff in effect"; icode:15; itype:3; classtype:misc-activity; sid:2100403; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100403
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Precedence Cutoff in effect"; icode:15; itype:3; classtype:misc-activity; sid:2100403; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Precedence Cutoff in effect** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Protocol Unreachable"; icode:2; itype:3; classtype:misc-activity; sid:2100404; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100404
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Protocol Unreachable"; icode:2; itype:3; classtype:misc-activity; sid:2100404; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Protocol Unreachable** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Source Host Isolated"; icode:8; itype:3; classtype:misc-activity; sid:2100405; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100405
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Source Host Isolated"; icode:8; itype:3; classtype:misc-activity; sid:2100405; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Source Host Isolated** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Source Route Failed"; icode:5; itype:3; classtype:misc-activity; sid:2100406; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100406
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Destination Unreachable Source Route Failed"; icode:5; itype:3; classtype:misc-activity; sid:2100406; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Source Route Failed** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Echo Reply"; icode:0; itype:0; classtype:misc-activity; sid:2100408; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100408
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Echo Reply"; icode:0; itype:0; classtype:misc-activity; sid:2100408; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Echo Reply** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Fragment Reassembly Time Exceeded"; icode:1; itype:11; classtype:misc-activity; sid:2100410; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100410
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Fragment Reassembly Time Exceeded"; icode:1; itype:11; classtype:misc-activity; sid:2100410; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Fragment Reassembly Time Exceeded** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO IPV6 I-Am-Here"; icode:0; itype:34; classtype:misc-activity; sid:2100411; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100411
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO IPV6 I-Am-Here"; icode:0; itype:34; classtype:misc-activity; sid:2100411; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IPV6 I-Am-Here** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO IPV6 Where-Are-You"; icode:0; itype:33; classtype:misc-activity; sid:2100413; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100413
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO IPV6 Where-Are-You"; icode:0; itype:33; classtype:misc-activity; sid:2100413; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IPV6 Where-Are-You** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO IRDP router advertisement"; itype:9; reference:arachnids,173; reference:bugtraq,578; reference:cve,1999-0875; classtype:misc-activity; sid:2100363; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100363
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO IRDP router advertisement"; itype:9; reference:arachnids,173; reference:bugtraq,578; reference:cve,1999-0875; classtype:misc-activity; sid:2100363; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IRDP router advertisement** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,173|bugtraq,578|cve,1999-0875

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO IRDP router selection"; itype:10; reference:arachnids,174; reference:bugtraq,578; reference:cve,1999-0875; classtype:misc-activity; sid:2100364; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100364
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO IRDP router selection"; itype:10; reference:arachnids,174; reference:bugtraq,578; reference:cve,1999-0875; classtype:misc-activity; sid:2100364; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **IRDP router selection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,174|bugtraq,578|cve,1999-0875

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Information Request"; icode:0; itype:15; classtype:misc-activity; sid:2100417; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100417
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Information Request"; icode:0; itype:15; classtype:misc-activity; sid:2100417; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Information Request** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Mobile Host Redirect"; icode:0; itype:32; classtype:misc-activity; sid:2100419; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100419
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Mobile Host Redirect"; icode:0; itype:32; classtype:misc-activity; sid:2100419; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Mobile Host Redirect** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Mobile Registration Reply"; icode:0; itype:36; classtype:misc-activity; sid:2100421; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100421
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Mobile Registration Reply"; icode:0; itype:36; classtype:misc-activity; sid:2100421; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Mobile Registration Reply** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Mobile Registration Request"; icode:0; itype:35; classtype:misc-activity; sid:2100423; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100423
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Mobile Registration Request"; icode:0; itype:35; classtype:misc-activity; sid:2100423; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Mobile Registration Request** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING *NIX"; itype:8; content:"|10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F|"; depth:32; classtype:misc-activity; sid:2100366; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100366
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING *NIX"; itype:8; content:"|10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F|"; depth:32; classtype:misc-activity; sid:2100366; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING *NIX** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING BSDtype"; itype:8; content:"|08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17|"; depth:32; reference:arachnids,152; classtype:misc-activity; sid:2100368; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100368
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING BSDtype"; itype:8; content:"|08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17|"; depth:32; reference:arachnids,152; classtype:misc-activity; sid:2100368; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING BSDtype** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,152

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING BayRS Router"; itype:8; content:"|01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F|"; depth:32; reference:arachnids,438; reference:arachnids,444; classtype:misc-activity; sid:2100369; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100369
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING BayRS Router"; itype:8; content:"|01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F|"; depth:32; reference:arachnids,438; reference:arachnids,444; classtype:misc-activity; sid:2100369; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING BayRS Router** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,438|arachnids,444

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING BeOS4.x"; itype:8; content:"|00 00 00 00 00 00 00 00 00 00 00 00 08 09 0A 0B|"; depth:32; reference:arachnids,151; classtype:misc-activity; sid:2100370; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100370
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING BeOS4.x"; itype:8; content:"|00 00 00 00 00 00 00 00 00 00 00 00 08 09 0A 0B|"; depth:32; reference:arachnids,151; classtype:misc-activity; sid:2100370; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING BeOS4.x** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,151

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Cisco Type.x"; itype:8; content:"|AB CD AB CD AB CD AB CD AB CD AB CD AB CD AB CD|"; depth:32; reference:arachnids,153; classtype:misc-activity; sid:2100371; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100371
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Cisco Type.x"; itype:8; content:"|AB CD AB CD AB CD AB CD AB CD AB CD AB CD AB CD|"; depth:32; reference:arachnids,153; classtype:misc-activity; sid:2100371; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Cisco Type.x** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,153

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Flowpoint2200 or Network Management Software"; itype:8; content:"|01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10|"; depth:32; reference:arachnids,156; classtype:misc-activity; sid:2100373; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100373
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Flowpoint2200 or Network Management Software"; itype:8; content:"|01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10|"; depth:32; reference:arachnids,156; classtype:misc-activity; sid:2100373; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Flowpoint2200 or Network Management Software** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,156

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING IP NetMonitor Macintosh"; itype:8; content:"|A9| Sustainable So"; depth:32; reference:arachnids,157; classtype:misc-activity; sid:2100374; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100374
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING IP NetMonitor Macintosh"; itype:8; content:"|A9| Sustainable So"; depth:32; reference:arachnids,157; classtype:misc-activity; sid:2100374; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING IP NetMonitor Macintosh** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,157

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING LINUX/*BSD"; dsize:8; id:13170; itype:8; reference:arachnids,447; classtype:misc-activity; sid:2100375; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100375
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING LINUX/*BSD"; dsize:8; id:13170; itype:8; reference:arachnids,447; classtype:misc-activity; sid:2100375; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING LINUX/*BSD** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,447

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Microsoft Windows"; itype:8; content:"0123456789abcdefghijklmnop"; depth:32; reference:arachnids,159; classtype:misc-activity; sid:2100376; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100376
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Microsoft Windows"; itype:8; content:"0123456789abcdefghijklmnop"; depth:32; reference:arachnids,159; classtype:misc-activity; sid:2100376; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Microsoft Windows** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,159

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Network Toolbox 3 Windows"; itype:8; content:"================"; depth:32; reference:arachnids,161; classtype:misc-activity; sid:2100377; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100377
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Network Toolbox 3 Windows"; itype:8; content:"================"; depth:32; reference:arachnids,161; classtype:misc-activity; sid:2100377; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Network Toolbox 3 Windows** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,161

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Ping-O-MeterWindows"; itype:8; content:"OMeterObeseArmad"; depth:32; reference:arachnids,164; classtype:misc-activity; sid:2100378; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100378
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Ping-O-MeterWindows"; itype:8; content:"OMeterObeseArmad"; depth:32; reference:arachnids,164; classtype:misc-activity; sid:2100378; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Ping-O-MeterWindows** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,164

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Pinger Windows"; itype:8; content:"Data|00 00 00 00 00 00 00 00 00 00 00 00|"; depth:32; reference:arachnids,163; classtype:misc-activity; sid:2100379; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100379
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Pinger Windows"; itype:8; content:"Data|00 00 00 00 00 00 00 00 00 00 00 00|"; depth:32; reference:arachnids,163; classtype:misc-activity; sid:2100379; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Pinger Windows** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,163

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Seer Windows"; itype:8; content:"|88 04|              "; depth:32; reference:arachnids,166; classtype:misc-activity; sid:2100380; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100380
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Seer Windows"; itype:8; content:"|88 04|              "; depth:32; reference:arachnids,166; classtype:misc-activity; sid:2100380; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Seer Windows** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,166

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Sun Solaris"; dsize:8; itype:8; reference:arachnids,448; classtype:misc-activity; sid:2100381; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100381
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Sun Solaris"; dsize:8; itype:8; reference:arachnids,448; classtype:misc-activity; sid:2100381; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Sun Solaris** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,448

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING WhatsupGold Windows"; itype:8; content:"WhatsUp - A Netw"; depth:32; reference:arachnids,168; classtype:misc-activity; sid:2100482; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100482
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING WhatsupGold Windows"; itype:8; content:"WhatsUp - A Netw"; depth:32; reference:arachnids,168; classtype:misc-activity; sid:2100482; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING WhatsupGold Windows** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,168

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Windows"; itype:8; content:"abcdefghijklmnop"; depth:16; reference:arachnids,169; classtype:misc-activity; sid:2100382; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100382
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING Windows"; itype:8; content:"abcdefghijklmnop"; depth:16; reference:arachnids,169; classtype:misc-activity; sid:2100382; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING Windows** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,169

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING speedera"; itype:8; content:"89|3A 3B|<=>?"; depth:100; classtype:misc-activity; sid:2100480; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100480
`alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING speedera"; itype:8; content:"89|3A 3B|<=>?"; depth:100; classtype:misc-activity; sid:2100480; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING speedera** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING"; icode:0; itype:8; classtype:misc-activity; sid:2100384; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100384
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO PING"; icode:0; itype:8; classtype:misc-activity; sid:2100384; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **PING** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Redirect for TOS and Host"; icode:3; itype:5; classtype:misc-activity; sid:2100436; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100436
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Redirect for TOS and Host"; icode:3; itype:5; classtype:misc-activity; sid:2100436; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Redirect for TOS and Host** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Redirect for TOS and Network"; icode:2; itype:5; classtype:misc-activity; sid:2100437; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100437
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Redirect for TOS and Network"; icode:2; itype:5; classtype:misc-activity; sid:2100437; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Redirect for TOS and Network** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Router Advertisement"; icode:0; itype:9; reference:arachnids,173; classtype:misc-activity; sid:2100441; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100441
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Router Advertisement"; icode:0; itype:9; reference:arachnids,173; classtype:misc-activity; sid:2100441; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Router Advertisement** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,173

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 7

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Router Selection"; icode:0; itype:10; reference:arachnids,174; classtype:misc-activity; sid:2100443; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100443
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Router Selection"; icode:0; itype:10; reference:arachnids,174; classtype:misc-activity; sid:2100443; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Router Selection** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,174

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO SKIP"; icode:0; itype:39; classtype:misc-activity; sid:2100445; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100445
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO SKIP"; icode:0; itype:39; classtype:misc-activity; sid:2100445; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **SKIP** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Source Quench"; icode:0; itype:4; classtype:bad-unknown; sid:2100477; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100477
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Source Quench"; icode:0; itype:4; classtype:bad-unknown; sid:2100477; rev:3; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Source Quench** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 3

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO TJPingPro1.1Build 2 Windows"; itype:8; content:"TJPingPro by Jim"; depth:32; reference:arachnids,167; classtype:misc-activity; sid:2100481; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100481
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO TJPingPro1.1Build 2 Windows"; itype:8; content:"TJPingPro by Jim"; depth:32; reference:arachnids,167; classtype:misc-activity; sid:2100481; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **TJPingPro1.1Build 2 Windows** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,167

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 6

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Timestamp Reply"; icode:0; itype:14; classtype:misc-activity; sid:2100451; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100451
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Timestamp Reply"; icode:0; itype:14; classtype:misc-activity; sid:2100451; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Timestamp Reply** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Timestamp Request"; icode:0; itype:13; classtype:misc-activity; sid:2100453; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100453
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Timestamp Request"; icode:0; itype:13; classtype:misc-activity; sid:2100453; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Timestamp Request** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Traceroute ipopts"; ipopts:rr; itype:0; reference:arachnids,238; classtype:misc-activity; sid:2100455; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100455
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Traceroute ipopts"; ipopts:rr; itype:0; reference:arachnids,238; classtype:misc-activity; sid:2100455; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Traceroute ipopts** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : arachnids,238

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 8

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Traceroute"; icode:0; itype:30; classtype:misc-activity; sid:2100456; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100456
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO Traceroute"; icode:0; itype:30; classtype:misc-activity; sid:2100456; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Traceroute** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO redirect host"; icode:1; itype:5; reference:arachnids,135; reference:cve,1999-0265; classtype:bad-unknown; sid:2100472; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100472
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO redirect host"; icode:1; itype:5; reference:arachnids,135; reference:cve,1999-0265; classtype:bad-unknown; sid:2100472; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **redirect host** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : arachnids,135|cve,1999-0265

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO redirect net"; icode:0; itype:5; reference:arachnids,199; reference:cve,1999-0265; classtype:bad-unknown; sid:2100473; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100473
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO redirect net"; icode:0; itype:5; reference:arachnids,199; reference:cve,1999-0265; classtype:bad-unknown; sid:2100473; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **redirect net** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : bad-unknown

URL reference : arachnids,199|cve,1999-0265

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO traceroute ipopts"; ipopts:rr; itype:0; reference:arachnids,238; classtype:attempted-recon; sid:2100475; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100475
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO traceroute ipopts"; ipopts:rr; itype:0; reference:arachnids,238; classtype:attempted-recon; sid:2100475; rev:4; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **traceroute ipopts** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,238

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 4

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO traceroute"; itype:8; ttl:1; reference:arachnids,118; classtype:attempted-recon; sid:2100385; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100385
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO traceroute"; itype:8; ttl:1; reference:arachnids,118; classtype:attempted-recon; sid:2100385; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **traceroute** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-recon

URL reference : arachnids,118

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO unassigned type 1"; icode:0; itype:1; classtype:misc-activity; sid:2100458; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100458
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO unassigned type 1"; icode:0; itype:1; classtype:misc-activity; sid:2100458; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **unassigned type 1** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO unassigned type 2"; icode:0; itype:2; classtype:misc-activity; sid:2100460; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100460
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO unassigned type 2"; icode:0; itype:2; classtype:misc-activity; sid:2100460; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **unassigned type 2** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO unassigned type 7"; icode:0; itype:7; classtype:misc-activity; sid:2100462; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100462
`#alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL ICMP_INFO unassigned type 7"; icode:0; itype:7; classtype:misc-activity; sid:2100462; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **unassigned type 7** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL ICMP_INFO Address Mask Reply"; icode:0; itype:18; classtype:misc-activity; sid:2100386; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100386
`#alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL ICMP_INFO Address Mask Reply"; icode:0; itype:18; classtype:misc-activity; sid:2100386; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Address Mask Reply** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL ICMP_INFO Information Reply"; icode:0; itype:16; classtype:misc-activity; sid:2100415; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100415
`#alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL ICMP_INFO Information Reply"; icode:0; itype:16; classtype:misc-activity; sid:2100415; rev:6; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Information Reply** 

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

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp any any -> any any (msg:"GPL ICMP_INFO Destination Unreachable Communication Administratively Prohibited"; icode:13; itype:3; classtype:misc-activity; sid:2100485; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100485
`#alert icmp any any -> any any (msg:"GPL ICMP_INFO Destination Unreachable Communication Administratively Prohibited"; icode:13; itype:3; classtype:misc-activity; sid:2100485; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Communication Administratively Prohibited** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp any any -> any any (msg:"GPL ICMP_INFO Destination Unreachable Communication with Destination Host is Administratively Prohibited"; icode:10; itype:3; classtype:misc-activity; sid:2100486; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100486
`#alert icmp any any -> any any (msg:"GPL ICMP_INFO Destination Unreachable Communication with Destination Host is Administratively Prohibited"; icode:10; itype:3; classtype:misc-activity; sid:2100486; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Communication with Destination Host is Administratively Prohibited** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



#alert icmp any any -> any any (msg:"GPL ICMP_INFO Destination Unreachable Communication with Destination Network is Administratively Prohibited"; icode:9; itype:3; classtype:misc-activity; sid:2100487; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

# 2100487
`#alert icmp any any -> any any (msg:"GPL ICMP_INFO Destination Unreachable Communication with Destination Network is Administratively Prohibited"; icode:9; itype:3; classtype:misc-activity; sid:2100487; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
` 

Name : **Destination Unreachable Communication with Destination Network is Administratively Prohibited** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : misc-activity

URL reference : Not defined

CVE reference : Not defined

Creation date : 2010-09-23

Last modified date : 2010-09-23

Rev version : 5

Category : ICMP_INFO

Severity : Not defined

Ruleset : GPL

Malware Family : Not defined

Type : SID

Performance Impact : Not defined



