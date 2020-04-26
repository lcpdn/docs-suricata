# 2003192
`alert tcp $EXTERNAL_NET any -> $HOME_NET 5060 (msg:"ET VOIP INVITE Message Flood TCP"; flow:established,to_server; content:"INVITE"; depth:6; threshold: type both , track by_src, count 100, seconds 60; reference:url,doc.emergingthreats.net/2003192; classtype:attempted-dos; sid:2003192; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
` 

Name : **INVITE Message Flood TCP** 

Attack target : Not defined

Description : Not defined

Tags : Not defined

Affected products : Not defined

Alert Classtype : attempted-dos

URL reference : url,doc.emergingthreats.net/2003192

CVE reference : Not defined

Creation date : 2010-07-30

Last modified date : 2010-07-30

Rev version : 4

Category : VOIP

Severity : Not defined

Ruleset : ET

Malware Family : Not defined

Type : SID

Performance Impact : Not defined

