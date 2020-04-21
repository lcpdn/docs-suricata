#

# $Id: emerging-ciarmy.rules $

# Emerging Threats Ciarmy rules.

#

# Rules to block CiArmy.com identified Top Attackers (www.ciarmy.com)

#

# More information available at www.emergingthreats.net

#

# Please submit any feedback or ideas to emerging@emergingthreats.net or the emerging-sigs mailing list

#

#*************************************************************

#

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

#

alert ip [1.11.100.135,1.168.120.198,1.171.10.247,1.171.145.253,1.173.225.177,1.174.25.6,1.174.74.150,1.179.128.124,1.179.153.18,1.179.173.2,1.179.199.114,1.186.220.253,1.188.193.211,1.189.79.7,1.189.88.70,1.192.131.153,1.192.192.4,1.192.192.6,1.192.192.8,1.192.195.11,1.192.195.5,1.192.195.8,1.193.112.135,1.196.216.140,1.202.128.68,1.202.156.201,1.202.240.163,1.203.115.140,1.203.115.64,1.203.161.58,1.203.65.156,1.203.80.2,1.203.93.254,1.207.63.62,1.209.72.151,1.209.72.154,1.214.245.27,1.222.141.242,1.224.166.120,1.224.166.240,1.227.37.35,1.227.5.115,1.231.158.6,1.238.61.87,1.243.12.150,1.245.218.13,1.245.248.204,1.249.31.138,1.250.176.173,1.250.176.181] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 1"; reference:url,www.cinsscore.com; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2403300; rev:56872; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag CINS, signature_severity Major, created_at 2013_10_08, updated_at 2020_04_20;)

