import os, sys, subprocess


domain = input("Enter domain name: ")
modSecFile = "/etc/apache2/modsecurity-crs/coreruleset-3.3.2/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
modSecRuleFormat = "SecRule REQUEST_HEADERS:Host \"@streq {}\" \"id:{},phase:1,ctl:ruleRemoveByID={}\""
relevantLogs = subprocess.Popen(f"sudo cat /var/log/apache2/modsec_audit.log | grep {domain}", stdout=subprocess.PIPE, shell=True).communicate()[0].decode()
previousErrors, addedExceptionCount = [], 0
with open(modSecFile, "r") as securityExceptions:
	exceptionData = securityExceptions.read().split("\n")
	while exceptionData[-1].replace("\n", "").strip() == "":
		del exceptionData[-1]
	endExceptionID = int(exceptionData[-1].split("id:",1)[1].split(",", 1)[0])
subprocess.Popen(f"sudo cp {modSecFile} {modSecFile}.bak", stdout=subprocess.PIPE, shell=True).communicate()[0].decode()
try:
	for index, log in enumerate(relevantLogs.split("\n")):
		try:
			ruleID = log.split("id \"", 1)[1].split("\"", 1)[0]
			if ruleID not in previousErrors:
				print(f"{index+1}: {log}")
				confirmException = input(f"Add exception for rule {ruleID}? [Y|N]: ")
				if "y" in confirmException.lower():
					print(f"Excluding rule {ruleID} from {modSecFile}...")
					endExceptionID += 1
					newModSecRule = modSecRuleFormat.format(domain, endExceptionID, ruleID)
					with open(modSecFile, "w+") as newModSecFile:
						exceptionData.append(newModSecRule)
						for line in exceptionData:
							newModSecFile.write(line+"\n")
					previousErrors.append(ruleID)
				elif "n" in confirmException.lower():
					print("Ignoring...")
					previousErrors.append(ruleID)
				else:
					...
		except IndexError:
			pass
		except KeyboardInterrupt:
			print("")
			abort = input("Quit? [Y|N] (N): ")
			if "y" in abort.lower():
				exit()
			else:
				print("")
		except EOFError:
			exit()
except:
	print("Error encountered. Restoring backup mod security file...")
	subprocess.Popen(f"sudo cp {modSecFile}.bak {modSecFile}", stdout=subprocess.PIPE, shell=True).communicate()[0].decode()
else:
	print("You must restart apache to apply changes.")
	restartApache = input("Restart now? [Y|N]: ")
	if "y" in restartApache.lower():
		subprocess.Popen("sudo systemctl restart apache2", stdout=subprocess.PIPE, shell=True).communicate()[0].decode()
	print("Complete!")
