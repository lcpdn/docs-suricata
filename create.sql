CREATE DATABASE suricata_docs;
USE suricata_docs;
CREATE USER 'suricata'@'localhost' IDENTIFIED BY 'SURICATA';
CREATE TABLE documentation
(	
	id INT PRIMARY KEY NOT NULL,
	rule TEXT,
	file VARCHAR(100),
	name TEXT,
	attack_target TEXT,
	description TEXT,
	tag TEXT,
	affected_products TEXT,
	classtype VARCHAR(100),
	url_reference TEXT,
	cve_reference TEXT,
	creation_date DATE,
	rev INT(2),
	signature_deployment VARCHAR(100),
	last_modified_date DATE,
	category  VARCHAR(100),
	severity  VARCHAR(100),
	ruleset  VARCHAR(100),
	malware_family TEXT,
	type  VARCHAR(100)
);
GRANT ALL PRIVILEGES ON * . * TO 'suricata'@'localhost';
