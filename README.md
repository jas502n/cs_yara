# cs_yara
check cs yara rules

![](./images/cs-beacon.png)


## powershell check
```
powershell -command "Get-Process | ForEach-Object {./yara64.exe beaconEye.yar $_.ID -s}"
```

![](./images/beaconEye.png)
