import json
import sys
import mysql.connector 



#Open file
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
		rule=alert
		file=rulefile
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
        #Connect to database
		conn = mysql.connector.connect(host="localhost",user="suricata",password="SURICATA", database="suricata_docs")
		cursor = conn.cursor()
		ruleobj={"sid": alert_sid, "rule": rule, "file":file, "name":name, "attack_target":attack_target, "description":description, "tag":tag, "affected_products":affected_products, "classtype":classtype, "url_reference":url_reference, "cve_reference":cve_reference, "creation_date":creation_date, "rev":rev, "signature_deployment":signature_deployment, "last_modified_date":last_modified_date, "category":category, "severity":severity, "ruleset":ruleset, "malware_family":malware_family, "type":type}
		cursor.execute("""INSERT INTO documentation (sid,rule,file,name,attack_target,description,tag,affected_products,classtype,url_reference,cve_reference,creation_date,rev,signature_deployment,last_modified_date,category,severity,ruleset,malware_family,type) VALUES(%(sid)s, %(rule)s, %(file)s, %(name)s, %(attack_target)s, %(description)s, %(tag)s, %(affected_products)s, %(classtype)s, %(url_reference)s, %(cve_reference)s, %(creation_date)s, %(rev)s, %(signature_deployment)s, %(last_modified_date)s, %(category)s, %(severity)s, %(ruleset)s, %(malware_family)s, %(type)s)""", ruleobj)
		conn.commit()
		cursor.close()

