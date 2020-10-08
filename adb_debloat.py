#!/usr/bin/env python3

###########################################################################################
#
# Remove Telia backdoors from ADB EA4201N router
# https://github.com/antnks/debloat-telia-adb
#
# This script uses the leaked tadmin password:
# https://full-disclosure.eu/reports/2019/FDEU-CVE-2019-10222-telia-savitarna-backdoor.html
#
###########################################################################################

import requests
import hashlib
import hmac

def extract_html(htmlstr, marker, end):
	idx = htmlstr.find(marker)
	subhtml = htmlstr[idx + len(marker):]
	idx = subhtml.find(end)
	return subhtml[:idx]

def adb_post(url, postdata):
	url = baseaddr + url
	res = session.get (url)
	html = res.content.decode("utf-8")
	action_key = extract_html(html, "name=\"action__key\" value=\"", "\"")
	
	postdata["action__key"] = action_key
	postdata["apply"] = "Apply"

	return session.post(url, data=postdata, allow_redirects=False)

# default values after factory reset
adminuser = "tadmin"
adminpass = "hqMV8Wps"
baseaddr = "http://192.168.1.254"

##### Get nonce value
session = requests.Session()
url = baseaddr + "/ui/login"
try:
	res = session.get(url, timeout=10)
except:
	print("[ADB] Error: could not connect")
	print("[ADB] Make sure you are connected to port LAN1 and the router is up")
	exit()
html = res.content.decode("utf-8")

nonce = extract_html(html, "name=\"nonce\" value=\"", "\"")
code1 = extract_html(html, "name='code1' value='", "'")
code2 = extract_html(html, "name='code2' value='", "'")
code3 = extract_html(html, "name='code3' value='", "'")
userPwd = hmac.new(bytes(nonce, "latin-1"), bytes(adminpass, "latin-1"), digestmod=hashlib.sha256).hexdigest().lower()

##### Login
postdata = {"userName":adminuser, "language":"EN", "login":"Login", "userPwd":userPwd, "nonce":nonce, "code1":code1, "code2":code2, "code3":code3}
res = session.post(url, data=postdata, allow_redirects=False)
if res.status_code != 302:
	print("[ADB] Error: could not login, status code: " + str(res.status_code))
	print("[ADB] Please try factory reset before running this script")
	exit()
print("[ADB] Login: OK")

##### Disable users
res = adb_post("/ui/dboard/settings/management/users", {"localEnable_1":"true"})
if res.status_code != 200:
	print("[ADB] Error: could not change setting, status code: " + str(res.status_code))
	exit()
print("[ADB] Disable users and remote web access: OK")

##### Remove management VLAN interfaces
print("[ADB] Deleting VLAN bridges...")
url = baseaddr + "/ui/dboard/settings/netif?action=delipif&ipif="
for i in [4,5,6,7]:
	res = session.get(url + str(i), allow_redirects=False)
	if res.status_code != 302:
		print("[ADB] Waring: could not delete bridge " + str(i) + ", skipping, status code: " + str(res.status_code))
print("[ADB] Delete VLAN bridges: done")

##### Add remaining LAN interfaces to bridge
print("[ADB] Adding ports 3 and 4 to LAN...")
url = baseaddr + "/ui/dboard/settings/netif/bridge?if=1&action=addport&ifpath=Device.Ethernet.Interface."
for i in [3,4]:
	res = session.get(url + str(i), allow_redirects=False)
	if res.status_code != 302:
		print("[ADB] Waring: could not add port " + str(i) + " to LAN bridge, skipping, status code: " + str(res.status_code))
print("[ADB] Add LAN ports: done")

##### Disable TR069 daemon
res = adb_post("/ui/dboard/settings/management/tr069", {"enableCwmp":"false", "acsProtocol":"http", "acsHost":"127.0.0.1", "acsPort":"7547", "acsPath":"cpeserver%2Facs", "tlsVersion":"Auto", "tlsCheckExists":"true", "tlsCheck":"CertInvalid", "tlsCheck":"CertRevoked", "tlsCheck":"CertExpired", "tlsCheck":"CertNotActivated", "tlsCheck":"CertSignerNotFound", "tlsCheck":"CNMatch", "acsUsername":"teo_acs", "acsPassword":"**********", "informInterface":"Device.IP.Interface.1", "connreqIf":"Auto", "enableFallbackIntf":"false", "connreqPort":"80", "connreqPath":"cpe", "connreqUsername":"", "connreqPassword":"", "ACLAddr0":"127.0.0.1", "ACLMask0":"255.255.255.255"})
if res.status_code != 200:
	print("[ADB] Error: could not change setting, status code: " + str(res.status_code))
	exit()
print("[ADB] Disable TR069: OK")

##### Disable TR069 inform
res = adb_post("/ui/dboard/settings/management/tr069/inform", {"enablePeriodic":"false", "periodicInterval":"21600", "minRetryInterval":"5"})
if res.status_code != 200:
	print("[ADB] Error: could not change setting, status code: " + str(res.status_code))
	exit()
print("[ADB] Disable periodic TR069 inform: OK")

##### Disable vulnerable UPnP
res = adb_post("/ui/dboard/settings/management/upnp", {"enable":"false", "autoWanInterface":"true", "wanInterface":"Device.IP.Interface.3", "lanInterface":"Device.IP.Interface.1"})
if res.status_code != 200:
	print("[ADB] Error: could not change setting, status code: " + str(res.status_code))
	exit()
print("[ADB] Disable UPnP: OK")

##### Disable Telnet service
res = adb_post("/ui/dboard/settings/management/telnetserver", {"localEnable":"false", "localPort":"23", "localInterface":"Device.IP.Interface.1", "localSessionlifetime":"300", "localACLAddr0":"", "localACLMask0":"", "remoteEnable":"false", "remotePort":"23", "remoteInterface":"ALL", "remoteSessionlifetime":"300", "remoteACLAddr0":"", "remoteACLMask0":""})
if res.status_code != 200:
	print("[ADB] Error: could not change setting, status code: " + str(res.status_code))
	exit()
print("[ADB] Disable Telnet server: OK")

##### Disable SSH service
res = adb_post("/ui/dboard/settings/management/sshserver", {"localEnable":"false", "localPort":"22", "localInterfacesExists":"true", "localInterfaces":"ALL", "localSessionlifetime":"300", "localACLAddr0":"", "localACLMask0":"", "remoteEnable":"false", "remotePort":"8022", "remoteInterfacesExists":"true", "remoteInterfaces":"Device.IP.Interface.3", "remoteSessionlifetime":"300", "remoteACLAddr0":"", "remoteACLMask0":""})
if res.status_code != 200:
	print("[ADB] Error: could not change setting, status code: " + str(res.status_code))
	exit()
print("[ADB] Disable SSH server: OK")

##### Disable WAN access to web administration
res = adb_post("/ui/dboard/settings/management/webgui", {"localEnable":"true", "localProtocolExists":"true", "localProtocol":"HTTP", "localPort":"80", "localSecPort":"", "localHTTPSPort":"443", "localHTTPSSecPort":"", "localInterfaceExists":"true", "localInterface":"Device.IP.Interface.1", "localSessionlifetime":"900", "remoteEnable":"false", "remoteProtocolExists":"true", "remoteProtocol":"HTTPS", "remotePort":"", "remoteSecPort":"", "remoteHTTPSPort":"8443", "remoteHTTPSSecPort":"", "remoteInterfaceExists":"true", "remoteInterface":"ALL", "remoteSessionlifetime":"1800"})
if res.status_code != 200:
	print("[ADB] Error: could not change setting, status code: " + str(res.status_code))
	exit()
print("[ADB] Disable WAN web server: OK")

##### Remove whitelisted Telia IPs
print("[ADB] Removing remote ACL rules...")
url = baseaddr + "/ui/dboard/settings/management/webgui/webguiremoteacl?action=delete&ruleid="
for i in [1,2,3]:
	res = session.get(url + str(i), allow_redirects=False)
	if res.status_code != 302:
		print("[ADB] Waring: could not remove rule " + str(i) + ", skipping, status code: " + str(res.status_code))
print("[ADB] Remove remote ACL: done")

print("Done! Now login as " + adminuser + "/" + adminpass " and change the password")

