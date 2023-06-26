package CVE_2014_4210

import (
	"fmt"
	"qi4l/config"
	//"io/ioutil"
	"net/http"
	//"os"
)

func islive(u string, port string) int {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := "http://" + u + ":" + port + "/uddiexplorer/"
	request, err := http.NewRequest("GET", url, nil)
	request.Header.Set("User-Agent", config.Fakeua())
	if err != nil {
		return -1
	}
	response, err := client.Do(request)
	if err != nil {
		return -1
	}
	defer response.Body.Close()
	//body, err := ioutil.ReadAll(response.Body)
	//fmt.Println("body:", string(body))

	status := response.StatusCode
	return status
}

func Run(u string, port string) {

	if islive(u, port) == 200 {
		url := "http://" + u + ":" + port + "/uddiexplorer/"
		fmt.Printf("[+] The target Weblogic UDDI module is exposed!\n[+] The path is: %s \n[+] Please verify the SSRF vulnerability!\n", url)
	} else {
		fmt.Printf("[-] The target Weblogic UDDI module default path does not exist!\n")
	}

}
