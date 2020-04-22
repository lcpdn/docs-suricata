import json
import sys
rulefile=sys.argv[1]
with open('desc.json') as f:
    content = json.load(f)

def display(name):
		if name:
			return name
		else:
			return "Not defined"
# Using readlines() 
file1 = open(rulefile, 'r') 
Lines = file1.readlines() 
	
count = 0
# Strips the newline character 
for line in Lines:
	if "alert" in line :
		alert=line
		alert_sid=alert[alert.find(" sid")+5:alert.find(" sid")+12]			
		i=alert_sid
		try:
			content[str(i)]
		except:
			pass
		name=content[str(i)]["name"]	
		attack_target=content[str(i)]["attack_target"]
		description=content[str(i)]["description"]
		tag=content[str(i)]["tag"]
		affected_products=content[str(i)]["affected_products"]
		classtype=content[str(i)]["classtype"]
		url_reference=content[str(i)]["url_reference"]
		cve_reference=content[str(i)]["cve_reference"]
		creation_date=content[str(i)]["creation_date"]
		rev=content[str(i)]["rev"]
		signature_deployment=content[str(i)]["signature_deployment"]
		last_modified_date=content[str(i)]["last_modified_date"]
		category=content[str(i)]["category"]
		severity=content[str(i)]["severity"]
		ruleset=content[str(i)]["ruleset"]
		malware_family=content[str(i)]["malware_family"]
		type=content[str(i)]["type"]
		performance_impact=content[str(i)]["performance_impact"]
		print("# "+alert_sid)
		print("`"+alert+"` \n")
		print("Name : **"+display(name)+"** \n")
		print("Attack target : "+display(attack_target)+"\n")
		print("Description : "+display(description)+"\n")
		print("Tags : "+display(tag)+"\n")
		print("Affected products : "+display(affected_products)+"\n")
		print("Alert Classtype : "+display(classtype)+"\n")
		print("URL reference : "+display(url_reference)+"\n")
		print("CVE reference : "+display(cve_reference)+"\n")
		print("Creation date : "+display(creation_date)+"\n")
		print("Last modified date : "+display(last_modified_date)+"\n")
		print("Rev version : "+display(rev)+"\n")
		print("Category : "+display(category)+"\n")
		print("Severity : "+display(severity)+"\n")
		print("Ruleset : "+display(ruleset)+"\n")
		print("Malware Family : "+display(malware_family)+"\n")
		print("Type : "+display(type)+"\n")
		print("Performance Impact : "+display(performance_impact)+"\n")
