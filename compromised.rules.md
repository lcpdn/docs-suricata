#

# $Id: emerging-compromised.rules

# Rules to block known hostile or compromised hosts. These lists are updated daily or better from many sources

#

#Sources include:

#

#  Daniel Gerzo's BruteForceBlocker

#  http://danger.rulez.sk/projects/bruteforceblocker/

#

#  The OpenBL

#  http://www.openbl.org/ (formerly sshbl.org)

#

#  And the Emerging Threats Sandnet and SidReporter Projects

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



#  VERSION 5409



#  Generated 2020-04-20 00:30:01 EDT



alert ip [101.36.164.114,101.78.168.168,101.78.240.26,103.114.106.36,103.120.203.142,103.125.191.136,103.13.122.156,103.133.105.180,103.136.40.100,103.138.109.68,103.14.229.253,103.216.112.230,103.221.222.179,103.226.248.72,103.228.110.24,103.27.237.67,103.69.71.58,103.89.90.114,103.99.1.31,103.99.3.45,104.131.53.42,104.131.73.105,104.140.114.106,104.140.242.35,104.154.165.78,104.154.244.76,104.200.134.151,104.200.134.181,104.206.252.71,104.211.143.123] any -> $HOME_NET any (msg:"ET COMPROMISED Known Compromised or Hostile Host Traffic group 1"; reference:url,doc.emergingthreats.net/bin/view/Main/CompromisedHosts; threshold: type limit, track by_src, seconds 60, count 1; classtype:misc-attack; sid:2500000; rev:5409; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag COMPROMISED, signature_severity Major, created_at 2011_04_28, updated_at 2020_04_20;)

