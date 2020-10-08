# debloat-telia-adb
Remove Telia backdoors from ADB EA4201N-G

![ADB EA4201N-G](https://user-images.githubusercontent.com/22909536/95460749-02a79b00-097e-11eb-9459-e183b28b958f.png)

# Make factory reset

After the [password leak](https://full-disclosure.eu/reports/2019/FDEU-CVE-2019-10222-telia-savitarna-backdoor.html) in 2019 Telia revoked the local access for user `tadmin`:
```
<cwmp:SetParameterValues xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<ParameterList SOAP-ENC:arrayType="cwmp:ParameterValueStruct[5]">
..
<ParameterValueStruct>
  <Name>Device.Users.User.1.X_ADB_LocalAccessCapable</Name>
  <Value xsi:type="xsd:boolean">0</Value>
</ParameterValueStruct>
<ParameterValueStruct>
  <Name>Device.Users.User.3.X_ADB_LocalAccessCapable</Name>
  <Value xsi:type="xsd:boolean">0</Value>
</ParameterValueStruct>
...
```
By making factory reset you will restore the full `tadmin` access.

# Run the script

The script will remove all the Telia backdoors and only leave local web access for user `tadmin`:

* disable `admin` and `ladmin` users
* disable VLAN interfaces
* disable TR069
* disable UPnP
* disable Telnet
* disable SSH
* disable IPTV

# Change the password

After you are done - don't forget to login and change the password
