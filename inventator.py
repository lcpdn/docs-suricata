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
		print(i+" is in "+rulefile+"\n")
		
