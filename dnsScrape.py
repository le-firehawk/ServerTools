import subprocess, sys, os, random


class Scraper:
    def __init__(self):
        self.__queries__, self.__CNAMEs___ = {}, []
        self.__testDNSServers__ = ["9.9.9.9", "36.255.51.239", "149.112.112.112", "84.200.70.40"]


    def __mutablePrint__(self, text, mute=False):
        if not mute:
            print(text)


    def run(self, FQDN, verbose, **kwargs):
        """Scrape various DNS servers to gather maximum A/CNAME records"""
        forceDNS, checkOtherSevers, quiet = kwargs.get("DNS", None), kwargs.get("recurse", True), kwargs.get("quiet", not verbose)
        if forceDNS:
            if forceDNS in self.__testDNSServers__:
                del self.__testDNSServers__[self.__testDNSServers__.index(forceDNS)]
            self.__testDNSServers__.insert(0, forceDNS)
        if len(self.__testDNSServers__) == 0:
            self.__mutablePrint__("All DNS servers have been exhausted. The website probably doesn't exist.", quiet)
            return None
        initialCheck = subprocess.Popen(f" nslookup {FQDN} {self.__testDNSServers__[0]}", stdout=subprocess.PIPE, shell=True).communicate()[0].decode()
        if "Non-authoritative answer:" in initialCheck:
            self.__mutablePrint__(f"{self.__testDNSServers__[0]} has provided an non-authoritative answer.\nIf the FQDN and DNS server differ, this is to be expected.\n", quiet)
        if f"can't find {FQDN.strip()}:" in initialCheck.lower():
            self.__mutablePrint__(f"{self.__testDNSServers__[0]} cannot locate {FQDN}... trying another server...\n", quiet)
            del self.__testDNSServers__[0]
            return self.run(FQDN, verbose, recurse=False)
        lastCNAME = FQDN
        while "canonical name = " in initialCheck:
            nextCNAME = initialCheck.split("canonical name = ")[1].split("\n")[0].strip()[:-1]
            self.__mutablePrint__(f"{lastCNAME} returned CNAME of {nextCNAME}... Recursing into it\n")
            initialCheck = subprocess.Popen(f" nslookup {nextCNAME} {self.__testDNSServers__[0]}", stdout=subprocess.PIPE, shell=True).communicate()[0].decode()
            self.__CNAMEs___.append([lastCNAME, nextCNAME])
            lastCNAME = nextCNAME
        FQDN = lastCNAME
        if "Non-authoritative answer:" in initialCheck:
            initialCheck = initialCheck.split("Non-authoritative answer:\n", 1)[1]
        else:
            initialCheck = initialCheck.split("\n\n", 1)[1]
        if not self.__queries__.get(FQDN, None):
            self.__queries__[FQDN] = {"ipv4": [], "ipv6": []}
        for entry in initialCheck.split("\n"):
            if "Address: " in entry:
                address = entry.split("Address: ")[1].strip()
                if address.count(".") == 3:
                    if address not in self.__queries__[FQDN].get("ipv4"):
                        self.__queries__[FQDN]["ipv4"].append(address)
                elif address.count(":") > 1:
                    if address not in self.__queries__[FQDN].get("ipv6"):
                        self.__queries__[FQDN]["ipv6"].append(address)
        if checkOtherSevers:
            for DNSserver in self.__testDNSServers__[1:]:
                self.run(FQDN, verbose, DNS=DNSserver, recurse=False, quiet=True)
        if len(self.__CNAMEs___) == 0:
            self.__CNAMEs___ = [[FQDN, FQDN]]
        return [self.__queries__], self.__CNAMEs___


def updateFile(data, file, verbose, giveFileWarining=False, forceName=None):
    """Update the given db file with the new DNS records"""
    if giveFileWarining:
        print("Changes are being applied to a temporary file without any existing configuration! Restart this program if this is unintended")
    with open(file, "r+") as DNSfile:
        DNSdata = DNSfile.read().split("\n")
        while "" in DNSdata:
            del DNSdata[DNSdata.index("")]
        if f"; SECTION: {file.split('.', 1)[1]}" in DNSdata:
            useSection = file.split('.', 1)[1]
            if verbose:
                print(f"Loading into section {useSection}")
            for index, subSection in enumerate(data[0]):
                subSectionData = subSection.get(data[1][index][1])
                if verbose:
                    print(subSectionData)
                if forceName:
                    subSectionName = forceName
                else:
                    subSectionName = data[1][index][1]
                    if subSectionName.count(".") > 2:
                        subSectionName = subSectionName.split(".", 1)[1][::-1].split(".", -1)[-2][::-1].capitalize()
                    elif subSectionName.count(".") == 1:
                        subSectionName = subSectionName.split(".")[0].capitalize()
                    else:
                        subSectionName = subSectionName.split(".", 1)[1].split(".")[0].capitalize()
                if f"; SUBSECTION: {subSectionName}" in DNSdata:
                    if verbose:
                        print(f"Loading into sub-section {subSectionName}")
                    startPoint, existingSubSection = DNSdata.index(f"; END SUBSECTION: {subSectionName}"), True
                    DNSdata.insert(startPoint+1, "")
                else:
                    if verbose:
                        print(f"Creating new sub-section {subSectionName}")
                    startPoint, existingSubSection = len(DNSdata) - 1, False
                    DNSdata.insert(startPoint, f"; END SUBSECTION: {subSectionName}")
                newCNAMEline = f"{data[1][index][0]}.\tIN\tCNAME\t{data[1][index][1]}."
                if newCNAMEline not in DNSdata and data[1][index][0] != data[1][index][1]:
                    DNSdata.insert(startPoint, newCNAMEline)
                for IPv6 in subSectionData.get("ipv6"):
                    newLine = f"{data[1][index][1]}.\tIN\tAAAA\t{IPv6}"
                    if newLine not in DNSdata:
                        DNSdata.insert(startPoint, newLine)
                for IPv4 in subSectionData.get("ipv4"):
                    newLine = f"{data[1][index][1]}.\tIN\tA\t{IPv4}"
                    if newLine not in DNSdata:
                        DNSdata.insert(startPoint, newLine)
                if not existingSubSection:
                    DNSdata.insert(startPoint, f"; SUBSECTION: {subSectionName}")
                DNSfile.seek(0)
                DNSfile.truncate()
                for line in DNSdata:
                    if verbose:
                        print(line)
                    if line.startswith("; END SUBSECTION"):
                        line += "\n"
                    DNSfile.write(f"{line}\n")
        else:
            print(f"Could not find section {file.split('.', 1)[1]}. Add the following line to the end of the file")
            print(f"; SECTION: {file.split('.', 1)[1]}")


if not os.path.exists("/usr/bin/nslookup") and not os.path.exists("/usr/sbin/nslookup") and not os.path.exists("/usr/local/bin/nslookup"):
    print("This script requires nslookup. Install it as part of the bind9-dnsutils package.")
if not os.path.exists("/tmp/db.empty"):
    subprocess.Popen("cp /etc/bind/db.empty /tmp/db.empty", stdout=subprocess.PIPE, shell=True).communicate()[0].decode()
defaultDBFile = "/tmp/db.empty"
scraper = Scraper()
try:
    FQDN = sys.argv[1]
    if ("--file" in sys.argv or "-f" in sys.argv) and os.path.exists(sys.argv[sys.argv.index("--file" if "--file" in sys.argv else "-f") + 1]):
        dbFile = sys.argv[sys.argv.index("--file" if "--file" in sys.argv else "-f") + 1]
        giveFileWarining = False
    elif "--file" in sys.argv or "-f" in sys.argv:
        print(f"Was expecting file location, could not find {sys.argv[sys.argv.index('--file' if '--file' in sys.argv else '-f') + 1]}")
        exit()
    else:
        dbFile = defaultDBFile
        giveFileWarining = True
    if "--name" in sys.argv or "-n" in sys.argv:
        forceName = sys.argv[sys.argv.index("--name" if "--name" in sys.argv else "-n") + 1]
    else:
        forceName = None
    if "-v" in sys.argv or "--verbose" in sys.argv:
        verbose = True
    else:
        verbose = False
    if "--dns" in sys.argv or "-d" in sys.argv:
        manualServer = sys.argv[sys.argv.index("-d" if "-d" in sys.argv else "--dns") + 1]
        A_records, CNAMEs = scraper.run(FQDN, verbose, DNS=manualServer)
    else:
        A_records, CNAMEs = scraper.run(FQDN, verbose)
    updateFile([A_records, CNAMEs], dbFile, verbose, giveFileWarining, forceName)
except IndexError:
    print("No address entered!")
