#!/usr/bin/env python3
"""
WiFi Environment Scanner v2.0
─────────────────────────────
• Base OUI embebida (~600 vendors comunes) + descarga IEEE completa si hay internet
• Escaneo de clientes conectados a cada AP (MAC, vendor, señal)
• Whitelist de redes autorizadas
• Modo continuo con re-escaneo

Uso:
  sudo python3 wifi_scanner.py
  sudo python3 wifi_scanner.py --whitelist whitelist.txt
  sudo python3 wifi_scanner.py --rescan 30
  sudo python3 wifi_scanner.py --clients           # escanear clientes (requiere modo monitor)
  sudo python3 wifi_scanner.py --update-oui         # forzar descarga OUI IEEE
  sudo python3 wifi_scanner.py --oui-file oui.txt   # usar archivo OUI local
"""

import subprocess, re, json, argparse, sys, os, datetime, time, signal, threading

# ── COLORES TERMINAL ──────────────────────────────────────────────────────────

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── BASE OUI EMBEBIDA (~600 fabricantes más comunes) ──────────────────────────

EMBEDDED_OUI = {
    # ─── Apple ───
    "000A27":"Apple","000A95":"Apple","000D93":"Apple","0010FA":"Apple",
    "001124":"Apple","001451":"Apple","0016CB":"Apple","0017F2":"Apple",
    "0019E3":"Apple","001B63":"Apple","001CB3":"Apple","001D4F":"Apple",
    "001E52":"Apple","001F5B":"Apple","001FF3":"Apple","0021E9":"Apple",
    "002241":"Apple","002312":"Apple","002332":"Apple","002436":"Apple",
    "002500":"Apple","002507":"Apple","00254B":"Apple","002608":"Apple",
    "003065":"Apple","003EE1":"Apple","00569A":"Apple","006171":"Apple",
    "006D52":"Apple","00A040":"Apple","00B362":"Apple","00C610":"Apple",
    "00CDFE":"Apple","00DB70":"Apple","00F4B9":"Apple","00F76F":"Apple",
    "040CCE":"Apple","041552":"Apple","042665":"Apple","044BED":"Apple",
    "046C59":"Apple","04D3CF":"Apple","04E536":"Apple","04F13E":"Apple",
    "04F7E4":"Apple","080007":"Apple","0C3021":"Apple","0C4DE9":"Apple",
    "0C5101":"Apple","0C74C2":"Apple","0C771A":"Apple","0CBC9F":"Apple",
    "0CD746":"Apple","0CF3EE":"Apple","100417":"Apple","1040F3":"Apple",
    "1041A4":"Apple","10417F":"Apple","1093E9":"Apple","109ADD":"Apple",
    "10DDB1":"Apple","140C76":"Apple","141123":"Apple","14109F":"Apple",
    "148FC6":"Apple","14956B":"Apple","14BD61":"Apple","18AF61":"Apple",
    "18AF8F":"Apple","18E7F4":"Apple","18EE69":"Apple","18F643":"Apple",
    "1C1AC0":"Apple","1C36BB":"Apple","1C5CF2":"Apple","1C9148":"Apple",
    "1CABA7":"Apple","1CE62B":"Apple","203CAE":"Apple","20768F":"Apple",
    "207D74":"Apple","209BCD":"Apple","20A2E4":"Apple","20AB37":"Apple",
    "20C9D0":"Apple","24240E":"Apple","244B03":"Apple","2488FF":"Apple",
    "24A074":"Apple","24A2E1":"Apple","24AB81":"Apple","24F094":"Apple",
    "280B5C":"Apple","281878":"Apple","283737":"Apple","285AEB":"Apple",
    "286AB8":"Apple","286ABA":"Apple","28A02B":"Apple","28CFDA":"Apple",
    "28CFE9":"Apple","28E02C":"Apple","28E14C":"Apple","28E7CF":"Apple",
    "28F076":"Apple","2C1F23":"Apple","2C200B":"Apple","2C3361":"Apple",
    "2CB43A":"Apple","2CF0A2":"Apple","2CF0EE":"Apple","30636B":"Apple",
    "3090AB":"Apple","30F7C5":"Apple","3408BC":"Apple","34159E":"Apple",
    "34363B":"Apple","34A395":"Apple","34C059":"Apple","34E2FD":"Apple",
    "380F4A":"Apple","3816D1":"Apple","38484C":"Apple","38B54D":"Apple",
    "38C986":"Apple","38CADA":"Apple","3C0754":"Apple","3C15C2":"Apple",
    "3C2EFF":"Apple","3C2EF9":"Apple","3CAAF4":"Apple","3CD0F8":"Apple",
    "3CE072":"Apple","3CF5A6":"Apple","400831":"Apple","403004":"Apple",
    "40331A":"Apple","40A6D9":"Apple","40B395":"Apple","40D3AE":"Apple",
    "442A60":"Apple","4450B5":"Apple","44D884":"Apple","483B38":"Apple",
    "4860BC":"Apple","48746E":"Apple","48A195":"Apple","48BF6B":"Apple",
    "48D705":"Apple","48E9F1":"Apple","4C3275":"Apple","4C57CA":"Apple",
    "4C74BF":"Apple","4C8093":"Apple","4C8D79":"Apple","4CB199":"Apple",
    "500983":"Apple","5033D0":"Apple","503237":"Apple","50A67F":"Apple",
    "50EAD6":"Apple","544E45":"Apple","5477A9":"Apple","54AE27":"Apple",
    "54E43A":"Apple","54EAA8":"Apple","54FA3E":"Apple","581FAA":"Apple",
    "58404E":"Apple","585BE1":"Apple","5882A8":"Apple","589567":"Apple",
    "58B035":"Apple","5C5948":"Apple","5C8D4E":"Apple","5C9696":"Apple",
    "5C969D":"Apple","5C97F3":"Apple","5CADCF":"Apple","5CF5DA":"Apple",
    "5CF7E6":"Apple","5CF938":"Apple","60030D":"Apple","60128B":"Apple",
    "6033B2":"Apple","603552":"Apple","6069C0":"Apple","606944":"Apple",
    "60A37D":"Apple","60C547":"Apple","60D9C7":"Apple","60F445":"Apple",
    "60F81D":"Apple","60FACD":"Apple","60FEC5":"Apple","641CB0":"Apple",
    "642210":"Apple","6476BA":"Apple","649ABE":"Apple","64A3CB":"Apple",
    "64B0A6":"Apple","64E682":"Apple","680927":"Apple","6816F0":"Apple",
    "6817C6":"Apple","685BAE":"Apple","685B35":"Apple","6896A3":"Apple",
    "68A86D":"Apple","68AB1E":"Apple","68AE20":"Apple","68D93C":"Apple",
    "68DB96":"Apple","68DFDD":"Apple","68EF43":"Apple","68FEF7":"Apple",
    "6C3E6D":"Apple","6C4008":"Apple","6C4D73":"Apple","6C709F":"Apple",
    "6C72E7":"Apple","6C8DC1":"Apple","6C94F8":"Apple","6C96CF":"Apple",
    "6CC26B":"Apple","6CEC5A":"Apple","700B4F":"Apple","7014A6":"Apple",
    "702DE4":"Apple","703EAC":"Apple","70480F":"Apple","7056DC":"Apple",
    "705681":"Apple","70700D":"Apple","70A2B3":"Apple","70AAFE":"Apple",
    "70CD60":"Apple","70DEE2":"Apple","70E72C":"Apple","70ECE4":"Apple",
    "70F087":"Apple","743827":"Apple","7452C9":"Apple","748114":"Apple",
    "748D08":"Apple","749EAF":"Apple","74E1B6":"Apple","74E2F5":"Apple",
    "780413":"Apple","783A84":"Apple","784F43":"Apple","786C1C":"Apple",
    "789F70":"Apple","78A3E4":"Apple","78CA39":"Apple","78D75F":"Apple",
    "78FD94":"Apple","7C0191":"Apple","7C04D0":"Apple","7C11BE":"Apple",
    "7C5049":"Apple","7C6DF8":"Apple","7C6D62":"Apple","7CB733":"Apple",
    "7CC3A1":"Apple","7CC537":"Apple","7CD1C3":"Apple","7CF05F":"Apple",
    "80006E":"Apple","800184":"Apple","80029C":"Apple","8019FE":"Apple",
    "802154":"Apple","804971":"Apple","80626E":"Apple","8086F2":"Apple",
    "809B20":"Apple","80A856":"Apple","80B03D":"Apple","80BE05":"Apple",
    "80D605":"Apple","80EA96":"Apple","80E650":"Apple","80ED2C":"Apple",
    "843835":"Apple","84119E":"Apple","8455A5":"Apple","848506":"Apple",
    "848E0C":"Apple","8496D8":"Apple","84A134":"Apple","84B153":"Apple",
    "84FCAC":"Apple","84FCFE":"Apple","881FA1":"Apple","882364":"Apple",
    "886631":"Apple","8866A5":"Apple","8871B1":"Apple","88C663":"Apple",
    "88CB87":"Apple","88E87F":"Apple","88E9FE":"Apple","8C006D":"Apple",
    "8C2937":"Apple","8C2DAA":"Apple","8C5877":"Apple","8C5877":"Apple",
    "8C7B9D":"Apple","8C7C92":"Apple","8C8590":"Apple","8C8EF2":"Apple",
    "8CFABA":"Apple","900628":"Apple","9027E4":"Apple","903C92":"Apple",
    "9049FA":"Apple","90840D":"Apple","908D6C":"Apple","909C4A":"Apple",
    "90B0ED":"Apple","90B21F":"Apple","90B931":"Apple","90C1C6":"Apple",
    "90FD61":"Apple","941625":"Apple","9478B2":"Apple","949426":"Apple",
    "94B10A":"Apple","94BF2D":"Apple","94E96A":"Apple","94F6A3":"Apple",
    "983B16":"Apple","9C04EB":"Apple","9C20A9":"Apple","9C293F":"Apple",
    "9C2EA1":"Apple","9C35EB":"Apple","9C4FDA":"Apple","9C8BA0":"Apple",
    "9CD35B":"Apple","9CF387":"Apple","9CF48E":"Apple","A00798":"Apple",
    "A01828":"Apple","A0481C":"Apple","A04EA7":"Apple","A0D795":"Apple",
    "A0EDCD":"Apple","A40B32":"Apple","A41232":"Apple","A43135":"Apple",
    "A45E60":"Apple","A46706":"Apple","A4B197":"Apple","A4B805":"Apple",
    "A4C361":"Apple","A4D18C":"Apple","A4D1D2":"Apple","A4F1E8":"Apple",
    "A82066":"Apple","A85B78":"Apple","A85C2C":"Apple","A860B6":"Apple",
    "A8667F":"Apple","A86AE1":"Apple","A886DD":"Apple","A88808":"Apple",
    "A88E24":"Apple","A89FEC":"Apple","A8B1D4":"Apple","A8BBCF":"Apple",
    "A8FAD8":"Apple","AC293A":"Apple","AC3C0B":"Apple","AC61EA":"Apple",
    "AC7F3E":"Apple","AC87A3":"Apple","ACB57D":"Apple","ACBC32":"Apple",
    "ACCF5C":"Apple","ACFDEC":"Apple","B03495":"Apple","B065BD":"Apple",
    "B08177":"Apple","B0481A":"Apple","B09FBA":"Apple","B0A7B9":"Apple",
    "B0CA68":"Apple","B0F1A3":"Apple","B418D1":"Apple","B43A28":"Apple",
    "B44BD2":"Apple","B46293":"Apple","B47443":"Apple","B48B19":"Apple",
    "B4F0AB":"Apple","B8098A":"Apple","B817C2":"Apple","B81EF2":"Apple",
    "B8441A":"Apple","B844D9":"Apple","B853AC":"Apple","B85A73":"Apple",
    "B860B6":"Apple","B8634D":"Apple","B868A3":"Apple","B878C0":"Apple",
    "B88687":"Apple","B88D12":"Apple","B89044":"Apple","B8B2F8":"Apple",
    "B8C111":"Apple","B8C75D":"Apple","B8E856":"Apple","B8F6B1":"Apple",
    "B8FF61":"Apple","BC3BAF":"Apple","BC4CC4":"Apple","BC5436":"Apple",
    "BC6778":"Apple","BC6C21":"Apple","BC926B":"Apple","BC9FEF":"Apple",
    "BCA920":"Apple","BCEC5D":"Apple","BCFE8C":"Apple","C01ADA":"Apple",
    "C06394":"Apple","C0847A":"Apple","C088CE":"Apple","C09F42":"Apple",
    "C0A53E":"Apple","C0B658":"Apple","C0CCF8":"Apple","C0CECD":"Apple",
    "C0D012":"Apple","C0D3C0":"Apple","C0F2FB":"Apple","C42C03":"Apple",
    "C4B301":"Apple","C81EE7":"Apple","C82A14":"Apple","C8334B":"Apple",
    "C85B76":"Apple","C869CD":"Apple","C86F1D":"Apple","C87166":"Apple",
    "C8918F":"Apple","C89346":"Apple","C8B5B7":"Apple","C8B5AD":"Apple",
    "C8D083":"Apple","C8E0EB":"Apple","C8F650":"Apple","CC088D":"Apple",
    "CC20E8":"Apple","CC25EF":"Apple","CC2DB7":"Apple","CC4463":"Apple",
    "CC785F":"Apple","CC4EEC":"Apple","CCD281":"Apple",
    # ─── Samsung ───
    "000002":"Samsung","000024":"Samsung","0000F0":"Samsung",
    "000126":"Samsung","0007AB":"Samsung","000D6B":"Samsung",
    "000EF4":"Samsung","000FE4":"Samsung","0012FB":"Samsung",
    "001377":"Samsung","001599":"Samsung","0015B9":"Samsung",
    "001632":"Samsung","001698":"Samsung","001813":"Samsung",
    "001A8A":"Samsung","001B98":"Samsung","001CDC":"Samsung",
    "001E7D":"Samsung","001F6B":"Samsung","001FCC":"Samsung",
    "0021D1":"Samsung","0021D2":"Samsung","002339":"Samsung",
    "002491":"Samsung","002567":"Samsung","0026B8":"Samsung",
    "00E064":"Samsung","083D88":"Samsung","0C715D":"Samsung",
    "0C8910":"Samsung","0CD746":"Samsung","100BA6":"Samsung",
    "102279":"Samsung","1077B1":"Samsung","1093E9":"Samsung",
    "14568E":"Samsung","148949":"Samsung","180865":"Samsung",
    "182666":"Samsung","18227E":"Samsung","183A2D":"Samsung",
    "184ECE":"Samsung","18E2C2":"Samsung","1C5A3E":"Samsung",
    "1C62B8":"Samsung","1CE693":"Samsung","200C02":"Samsung",
    "206E9C":"Samsung","20D390":"Samsung","240926":"Samsung",
    "2429FE":"Samsung","2455CC":"Samsung","244B81":"Samsung",
    "2489BA":"Samsung","24C696":"Samsung","24DB96":"Samsung",
    "280EDB":"Samsung","28395E":"Samsung","2895BD":"Samsung",
    "2C0E3D":"Samsung","2C4401":"Samsung","30CBF8":"Samsung",
    "30D587":"Samsung","30D6C9":"Samsung","343111":"Samsung",
    "348A7B":"Samsung","34BE00":"Samsung","380195":"Samsung",
    "38017E":"Samsung","38169D":"Samsung","382DE8":"Samsung",
    "38A4ED":"Samsung","38D547":"Samsung","38ECE4":"Samsung",
    "3CBBFD":"Samsung","3CF7A4":"Samsung","3CFFE4":"Samsung",
    "402CF4":"Samsung","40966B":"Samsung","40D379":"Samsung",
    "44783E":"Samsung","44F459":"Samsung","480EEC":"Samsung",
    "480FCF":"Samsung","4C3C16":"Samsung","4CE676":"Samsung",
    "500F80":"Samsung","502E5C":"Samsung","503275":"Samsung",
    "506583":"Samsung","508CB1":"Samsung","508F4C":"Samsung",
    "50A4D0":"Samsung","50B7C3":"Samsung","50C8E5":"Samsung",
    "50F520":"Samsung","5440AD":"Samsung","5462E2":"Samsung",
    "549B12":"Samsung","54B802":"Samsung","580A20":"Samsung",
    "5C3A45":"Samsung","5C49E0":"Samsung","5C513C":"Samsung",
    "5CE0C5":"Samsung","6077E2":"Samsung","60834E":"Samsung",
    "60A10A":"Samsung","60AF6D":"Samsung","60D0A9":"Samsung",
    "643156":"Samsung","64B310":"Samsung","64B853":"Samsung",
    "680571":"Samsung","6817C6":"Samsung","6C2F2C":"Samsung",
    "6CDC08":"Samsung","700229":"Samsung","7019B7":"Samsung",
    "7071BC":"Samsung","70F927":"Samsung","744401":"Samsung",
    "78471D":"Samsung","788A20":"Samsung","78ABBB":"Samsung",
    "78D6F0":"Samsung","7C0A53":"Samsung","7C6456":"Samsung",
    "7CB60D":"Samsung","7CFA4D":"Samsung","802AA8":"Samsung",
    "8097D1":"Samsung","80CF41":"Samsung","845F04":"Samsung",
    "84119E":"Samsung","8425DB":"Samsung","882F98":"Samsung",
    "887019":"Samsung","888322":"Samsung","889B39":"Samsung",
    "88ADD2":"Samsung","88D274":"Samsung","8C7712":"Samsung",
    "9000DB":"Samsung","9013DA":"Samsung","906E6B":"Samsung",
    "90895F":"Samsung","940006":"Samsung","94350A":"Samsung",
    "946AB0":"Samsung","9852B1":"Samsung","98FD74":"Samsung",
    "9C021B":"Samsung","9C2A83":"Samsung","9C3AAF":"Samsung",
    "9CD917":"Samsung","A01082":"Samsung","A00BBA":"Samsung",
    "A02195":"Samsung","A052CB":"Samsung","A0219F":"Samsung",
    "A0CBFD":"Samsung","A46032":"Samsung","A48031":"Samsung",
    "A4C9A3":"Samsung","A80600":"Samsung","A84E3F":"Samsung",
    "A88195":"Samsung","AC36D0":"Samsung","ACD4E3":"Samsung",
    "B03856":"Samsung","B047BF":"Samsung","B0DF3A":"Samsung",
    "B0EC71":"Samsung","B0F1A3":"Samsung","B41513":"Samsung",
    "B473D5":"Samsung","B4EF39":"Samsung","B84DEE":"Samsung",
    "B857D8":"Samsung","B8D7AF":"Samsung","BC1485":"Samsung",
    "BC20A4":"Samsung","BC4760":"Samsung","BC8CCD":"Samsung",
    "BC8CE7":"Samsung","BCB1F3":"Samsung","C08997":"Samsung",
    "C0D3C0":"Samsung","C45006":"Samsung","C4731E":"Samsung",
    "C47DCC":"Samsung","C4ABB2":"Samsung","C8199D":"Samsung",
    "C838F4":"Samsung","C89C1D":"Samsung","CC0714":"Samsung",
    "CC3A61":"Samsung","D02544":"Samsung","D07E35":"Samsung",
    "D0176A":"Samsung","D0227B":"Samsung","D04F7E":"Samsung",
    "D05F64":"Samsung","D0667B":"Samsung","D09B05":"Samsung",
    "D0C1B1":"Samsung","D0D7BE":"Samsung","D0F025":"Samsung",
    "D42F13":"Samsung","D487D8":"Samsung","D831CF":"Samsung",
    "D8906D":"Samsung","D8C4E9":"Samsung","DC7144":"Samsung",
    "DCA43D":"Samsung","DCC8F5":"Samsung","DCCF96":"Samsung",
    "E0CBEE":"Samsung","E0DB10":"Samsung","E439D8":"Samsung",
    "E440E2":"Samsung","E44C6C":"Samsung","E498D6":"Samsung",
    "E49A79":"Samsung","E4B021":"Samsung","E4E0C5":"Samsung",
    "E4F8EF":"Samsung","E83A12":"Samsung","E8039A":"Samsung",
    "E84ECE":"Samsung","EC1F72":"Samsung","EC9BF3":"Samsung",
    "F008F1":"Samsung","F01D2D":"Samsung","F025B7":"Samsung",
    "F04BF2":"Samsung","F07BCB":"Samsung","F09FC2":"Samsung",
    "F0D461":"Samsung","F0E77E":"Samsung","F44D30":"Samsung",
    "F47B5E":"Samsung","F4D9FB":"Samsung","F80CF3":"Samsung",
    "F84897":"Samsung","F8042E":"Samsung","F84D89":"Samsung",
    "F87394":"Samsung","FC191D":"Samsung","FCA183":"Samsung",
    # ─── Intel / WiFi chipsets ───
    "001111":"Intel","001302":"Intel","001320":"Intel","001517":"Intel",
    "0019D1":"Intel","001B21":"Intel","001CC0":"Intel","001DE0":"Intel",
    "001E64":"Intel","001E65":"Intel","001E67":"Intel","001F3B":"Intel",
    "001F3C":"Intel","002314":"Intel","002710":"Intel","003676":"Intel",
    "004033":"Intel","0050F1":"Intel","00A0C9":"Intel","080009":"Intel",
    "084049":"Intel","0CD292":"Intel","100BA9":"Intel","180373":"Intel",
    "24774C":"Intel","28C63F":"Intel","3413E8":"Intel","34028F":"Intel",
    "3864F1":"Intel","3C6AA7":"Intel","3CF862":"Intel","407C7D":"Intel",
    "441C12":"Intel","4C3488":"Intel","4CEB42":"Intel","502B73":"Intel",
    "5082D5":"Intel","50E085":"Intel","5489D5":"Intel","58A0CB":"Intel",
    "5C5F67":"Intel","5CD2E4":"Intel","600F18":"Intel","60D819":"Intel",
    "642200":"Intel","683E34":"Intel","6C8814":"Intel","74E5F9":"Intel",
    "7C5CF8":"Intel","7CE9D3":"Intel","80C5F2":"Intel","80E1BF":"Intel",
    "843A4B":"Intel","8C994D":"Intel","948FD3":"Intel","9C295F":"Intel",
    "A0369F":"Intel","A09347":"Intel","A442B0":"Intel","A4C494":"Intel",
    "A80381":"Intel","A82BB9":"Intel","AC678D":"Intel","B468A0":"Intel",
    "B4D5BD":"Intel","B80E66":"Intel","B8A38F":"Intel","C894BB":"Intel",
    "D0AB64":"Intel","D81220":"Intel","D8FC93":"Intel","DC8B28":"Intel",
    "E00AF6":"Intel","E4A7A0":"Intel","E8B1FC":"Intel","F40669":"Intel",
    "F48C50":"Intel","F4E9D4":"Intel","F8161D":"Intel","FC5B24":"Intel",
    # ─── Qualcomm / Atheros ───
    "000A85":"Qualcomm","000E6D":"Qualcomm","001217":"Qualcomm",
    "001765":"Qualcomm","001AEB":"Qualcomm","001DBA":"Qualcomm",
    "00213F":"Qualcomm","00242B":"Qualcomm","0026CB":"Qualcomm",
    "04CE14":"Qualcomm","1077B0":"Qualcomm","60C5AD":"Qualcomm",
    "640980":"Qualcomm","78E7D1":"Qualcomm","B41489":"Qualcomm",
    # ─── Huawei / Honor ───
    "000AEB":"Huawei","0012D2":"Huawei","001882":"Huawei","0025A5":"Huawei",
    "002568":"Huawei","002EC7":"Huawei","004F49":"Huawei","00664B":"Huawei",
    "0076E7":"Huawei","007A95":"Huawei","008675":"Huawei","009ACD":"Huawei",
    "00D0D0":"Huawei","00E0FC":"Huawei","04021F":"Huawei","042758":"Huawei",
    "04B0E7":"Huawei","04C06F":"Huawei","04F9D9":"Huawei","080087":"Huawei",
    "0819A6":"Huawei","0C37DC":"Huawei","0C45BA":"Huawei","0CE725":"Huawei",
    "100E7E":"Huawei","1008B1":"Huawei","1030C1":"Huawei","1047D6":"Huawei",
    "105172":"Huawei","10C61F":"Huawei","141BF5":"Huawei","148005":"Huawei",
    "14A0F8":"Huawei","14B968":"Huawei","20A680":"Huawei","20F3A3":"Huawei",
    "24094A":"Huawei","241F2C":"Huawei","244C07":"Huawei","247F3C":"Huawei",
    "24BCF8":"Huawei","28310E":"Huawei","286ED4":"Huawei","288B5D":"Huawei",
    "28A6DB":"Huawei","2C55D3":"Huawei","2CC553":"Huawei","2CE759":"Huawei",
    "30469A":"Huawei","30D17E":"Huawei","30F335":"Huawei","340455":"Huawei",
    "340AFF":"Huawei","342497":"Huawei","34CDBE":"Huawei","381629":"Huawei",
    "38373B":"Huawei","38BC1A":"Huawei","3C47D6":"Huawei","3C678C":"Huawei",
    "3C9F81":"Huawei","3CBDD8":"Huawei","3CF808":"Huawei","400C08":"Huawei",
    "405E80":"Huawei","40CB56":"Huawei","44556B":"Huawei","446AB7":"Huawei",
    "486276":"Huawei","487455":"Huawei","489B4F":"Huawei","48A472":"Huawei",
    "48DB50":"Huawei","4C5499":"Huawei","4CB16C":"Huawei","4CE943":"Huawei",
    "501A20":"Huawei","5005EF":"Huawei","502765":"Huawei","5028D4":"Huawei",
    "504334":"Huawei","509F27":"Huawei","50A72B":"Huawei","54A51B":"Huawei",
    "58181F":"Huawei","582AF7":"Huawei","586D8F":"Huawei","58B81A":"Huawei",
    "5C09D9":"Huawei","5C4CA9":"Huawei","5C7D5E":"Huawei","5CB395":"Huawei",
    "5CB43E":"Huawei","5CCE8E":"Huawei","608334":"Huawei","60DE44":"Huawei",
    "60E701":"Huawei","643415":"Huawei","6C5976":"Huawei","6C5C3D":"Huawei",
    "70193B":"Huawei","7054F5":"Huawei","707990":"Huawei","708A09":"Huawei",
    "70723C":"Huawei","70A8E3":"Huawei","74882A":"Huawei","749D79":"Huawei",
    "74A528":"Huawei","781DBA":"Huawei","7840E4":"Huawei","786A89":"Huawei",
    "78D7FB":"Huawei","78F557":"Huawei","7C110C":"Huawei","7C6097":"Huawei",
    "7CA1B3":"Huawei","7CC4B1":"Huawei","80717A":"Huawei","80B686":"Huawei",
    "80D09B":"Huawei","80D455":"Huawei","80E0A0":"Huawei","80FB06":"Huawei",
    "842185":"Huawei","844740":"Huawei","84742A":"Huawei","84A8E4":"Huawei",
    "84DBFC":"Huawei","88085A":"Huawei","881196":"Huawei","883FD3":"Huawei",
    "8C0D76":"Huawei","8C34FD":"Huawei","8C4101":"Huawei","9017AC":"Huawei",
    "9067F3":"Huawei","9074B4":"Huawei","908D78":"Huawei","9CE374":"Huawei",
    "A46565":"Huawei","A4A2E6":"Huawei","A8CA7B":"Huawei","A8F5AC":"Huawei",
    "AC4E91":"Huawei","AC853D":"Huawei","ACE215":"Huawei","ACE87B":"Huawei",
    "B0E595":"Huawei","B43052":"Huawei","B4CD27":"Huawei","B8BC1B":"Huawei",
    "BC25E0":"Huawei","BC7574":"Huawei","BC7670":"Huawei","C0F6C2":"Huawei",
    "C4054B":"Huawei","C40528":"Huawei","C40F09":"Huawei","C4FF1F":"Huawei",
    "C8D15E":"Huawei","CC53B5":"Huawei","CCA223":"Huawei","CCCC81":"Huawei",
    "D02DB3":"Huawei","D065CA":"Huawei","D0694C":"Huawei","D43614":"Huawei",
    "D440F0":"Huawei","D46AA8":"Huawei","D46E5C":"Huawei","D4612E":"Huawei",
    "D4A148":"Huawei","D4B110":"Huawei","D4F9A1":"Huawei","D8490B":"Huawei",
    "D863BD":"Huawei","D88AB5":"Huawei","DC094C":"Huawei","E0247F":"Huawei",
    "E09797":"Huawei","E0A3AC":"Huawei","E468A3":"Huawei","E4C2D1":"Huawei",
    "E80870":"Huawei","E8088B":"Huawei","E8CD2D":"Huawei","EC233D":"Huawei",
    "EC4C4D":"Huawei","F46271":"Huawei","F48E92":"Huawei","F4559C":"Huawei",
    "F46C7C":"Huawei","F4C714":"Huawei","F4E3FB":"Huawei","F80083":"Huawei",
    "F8019A":"Huawei","F83DFF":"Huawei","F8C600":"Huawei","FC2FB1":"Huawei",
    "FC48EF":"Huawei","FC883F":"Huawei",
    # ─── Xiaomi ───
    "002792":"Xiaomi","00D0CE":"Xiaomi","045928":"Xiaomi","0C1DC2":"Xiaomi",
    "100809":"Xiaomi","10D07A":"Xiaomi","141F78":"Xiaomi","149F3C":"Xiaomi",
    "181D27":"Xiaomi","1C81D1":"Xiaomi","20F1DB":"Xiaomi","24CF21":"Xiaomi",
    "286C07":"Xiaomi","288B5D":"Xiaomi","2C9D1E":"Xiaomi","30D9D9":"Xiaomi",
    "341298":"Xiaomi","34CE00":"Xiaomi","381789":"Xiaomi","38E7D8":"Xiaomi",
    "3CF862":"Xiaomi","40310D":"Xiaomi","442C05":"Xiaomi","484837":"Xiaomi",
    "50EC50":"Xiaomi","582101":"Xiaomi","5884E4":"Xiaomi","6000B4":"Xiaomi",
    "6401FC":"Xiaomi","64B473":"Xiaomi","64CC2E":"Xiaomi","68DFDD":"Xiaomi",
    "742D0A":"Xiaomi","74237A":"Xiaomi","7802F8":"Xiaomi","78112F":"Xiaomi",
    "78F882":"Xiaomi","7C1DD9":"Xiaomi","7C49EB":"Xiaomi","80AD16":"Xiaomi",
    "84F3EB":"Xiaomi","8886E2":"Xiaomi","8CBEBE":"Xiaomi","9003B7":"Xiaomi",
    "9478B2":"Xiaomi","98FAE3":"Xiaomi","9CC7A6":"Xiaomi","A0F492":"Xiaomi",
    "A4776F":"Xiaomi","AC61EA":"Xiaomi","ACBD1C":"Xiaomi","B088E3":"Xiaomi",
    "B0E235":"Xiaomi","C40615":"Xiaomi","C408E6":"Xiaomi","C46AB7":"Xiaomi",
    "CC9F7A":"Xiaomi","D4970B":"Xiaomi","D85B2A":"Xiaomi","D87EB6":"Xiaomi",
    "E47BE7":"Xiaomi","E8AB40":"Xiaomi","EC6C9A":"Xiaomi","F04F7C":"Xiaomi",
    "F0B429":"Xiaomi","F48B32":"Xiaomi","F8A45F":"Xiaomi","FC64BA":"Xiaomi",
    # ─── TP-Link ───
    "000AEB":"TP-Link","001427":"TP-Link","005A13":"TP-Link",
    "106028":"TP-Link","14CCE4":"TP-Link","14EBB6":"TP-Link",
    "185936":"TP-Link","1C3BF3":"TP-Link","1C61B4":"TP-Link",
    "202BC1":"TP-Link","24698E":"TP-Link","30B49E":"TP-Link",
    "30DE4B":"TP-Link","38A28C":"TP-Link","402B50":"TP-Link",
    "446CB3":"TP-Link","480EEC":"TP-Link","4CA003":"TP-Link",
    "503CC4":"TP-Link","5091E3":"TP-Link","54AF97":"TP-Link",
    "588694":"TP-Link","5C628B":"TP-Link","600194":"TP-Link",
    "60E327":"TP-Link","685DBB":"TP-Link","687F74":"TP-Link",
    "6CE873":"TP-Link","78A106":"TP-Link","841827":"TP-Link",
    "88E97E":"TP-Link","8C210A":"TP-Link","985072":"TP-Link",
    "9C216A":"TP-Link","A42BB0":"TP-Link","A464B8":"TP-Link",
    "AC1550":"TP-Link","B00594":"TP-Link","B09575":"TP-Link",
    "B8824F":"TP-Link","B8F883":"TP-Link","C025A2":"TP-Link",
    "C04A00":"TP-Link","C0E42D":"TP-Link","C4E984":"TP-Link",
    "C8E7D8":"TP-Link","CC3220":"TP-Link","CC7B35":"TP-Link",
    "D4206D":"TP-Link","D46E0E":"TP-Link","D80D17":"TP-Link",
    "D8473D":"TP-Link","DC74A8":"TP-Link","E0A1CE":"TP-Link",
    "E4D332":"TP-Link","E8DE27":"TP-Link","EC086B":"TP-Link",
    "EC172F":"TP-Link","ECA940":"TP-Link","F04F7C":"TP-Link",
    "F0A731":"TP-Link","F483CD":"TP-Link","F4EC38":"TP-Link",
    "F8D111":"TP-Link",
    # ─── Cisco / Meraki ───
    "00000C":"Cisco","000142":"Cisco","000164":"Cisco","0001C7":"Cisco",
    "000196":"Cisco","0001C9":"Cisco","000216":"Cisco","000294":"Cisco",
    "00036B":"Cisco","0003E3":"Cisco","00040B":"Cisco","0004C0":"Cisco",
    "0004DD":"Cisco","000553":"Cisco","00062A":"Cisco","00070D":"Cisco",
    "0007EB":"Cisco","00078E":"Cisco","00079B":"Cisco","0008E2":"Cisco",
    "0009B7":"Cisco","000A41":"Cisco","000A8A":"Cisco","000AF3":"Cisco",
    "000B85":"Cisco","000BFC":"Cisco","000C30":"Cisco","000C85":"Cisco",
    "000D28":"Cisco","000D29":"Cisco","000DA2":"Cisco","000DBC":"Cisco",
    "000DBD":"Cisco","000DED":"Cisco","000E08":"Cisco","000E38":"Cisco",
    "000E39":"Cisco","000E83":"Cisco","000E84":"Cisco","000ED6":"Cisco",
    "000ED7":"Cisco","000F23":"Cisco","000F24":"Cisco","000F34":"Cisco",
    "000F35":"Cisco","000F66":"Cisco","000F8F":"Cisco","000F90":"Cisco",
    "001005":"Cisco","001006":"Cisco","001007":"Cisco","00100B":"Cisco",
    "00100D":"Cisco","001011":"Cisco","001014":"Cisco","00101F":"Cisco",
    "001029":"Cisco","00102F":"Cisco","001079":"Cisco","00107B":"Cisco",
    "001094":"Cisco","0010A6":"Cisco","0010F6":"Cisco","0010FF":"Cisco",
    "001121":"Cisco","001209":"Cisco","001217":"Cisco","00127F":"Cisco",
    "001280":"Cisco","0012D9":"Cisco","0012DA":"Cisco","001320":"Cisco",
    "001321":"Cisco","00137F":"Cisco","001380":"Cisco","001393":"Cisco",
    "0013C3":"Cisco","0013C4":"Cisco","001443":"Cisco","00146C":"Cisco",
    "0014A8":"Cisco","0014A9":"Cisco","001544":"Cisco","001557":"Cisco",
    "001563":"Cisco","0015C6":"Cisco","0015C7":"Cisco","0015F9":"Cisco",
    "0015FA":"Cisco","0016B6":"Cisco","0016C7":"Cisco","0016C8":"Cisco",
    "001795":"Cisco","001796":"Cisco","001798":"Cisco","0017DF":"Cisco",
    "0017E0":"Cisco","00186B":"Cisco","00186D":"Cisco","001873":"Cisco",
    "00188B":"Cisco","00188D":"Cisco","0018B9":"Cisco","0018BA":"Cisco",
    "001922":"Cisco","00192F":"Cisco","001930":"Cisco","0019A9":"Cisco",
    "0019AA":"Cisco","0019E7":"Cisco","001A2F":"Cisco","001A30":"Cisco",
    "001A6C":"Cisco","001A6D":"Cisco","001A70":"Cisco","001AA1":"Cisco",
    "001AA2":"Cisco","001B0C":"Cisco","001B0D":"Cisco","001B2A":"Cisco",
    "001B2B":"Cisco","001B53":"Cisco","001B54":"Cisco","001B67":"Cisco",
    "001B8F":"Cisco","001B90":"Cisco","001BD4":"Cisco","001BD5":"Cisco",
    "001BD7":"Cisco","001C01":"Cisco","001C0E":"Cisco","001C0F":"Cisco",
    "001C10":"Cisco","001C57":"Cisco","001C58":"Cisco","001CDE":"Cisco",
    "0018F8":"Meraki","0C8DDB":"Meraki","682C7B":"Meraki","E8ED05":"Meraki",
    "AC17C8":"Meraki","34FD6F":"Meraki","8439BE":"Meraki","C8B5AD":"Meraki",
    # ─── Netgear ───
    "000FB5":"Netgear","00146C":"Netgear","001B2F":"Netgear",
    "001E2A":"Netgear","001F33":"Netgear","00223F":"Netgear",
    "002401":"Netgear","004033":"Netgear","00095B":"Netgear",
    "00204E":"Netgear","08028E":"Netgear","08BD43":"Netgear",
    "100D7F":"Netgear","100E7E":"Netgear","2004FA":"Netgear",
    "28C68E":"Netgear","30469A":"Netgear","3498B5":"Netgear",
    "3894ED":"Netgear","3C3786":"Netgear","3CCCFF":"Netgear",
    "405D82":"Netgear","44A56E":"Netgear","4C60DE":"Netgear",
    "504A6E":"Netgear","6038E0":"Netgear","6CB0CE":"Netgear",
    "744401":"Netgear","80F660":"Netgear","8C0461":"Netgear",
    "9420C1":"Netgear","9CCADF":"Netgear","9CD36D":"Netgear",
    "A003E6":"Netgear","A021B7":"Netgear","A040A0":"Netgear",
    "B03956":"Netgear","B0487A":"Netgear","B07FB9":"Netgear",
    "B0C745":"Netgear","C03F0E":"Netgear","C43DC7":"Netgear",
    "C4041E":"Netgear","CC4017":"Netgear","CC40D0":"Netgear",
    "DC9FA4":"Netgear","E0469A":"Netgear","E091F5":"Netgear",
    "E4F4C6":"Netgear","F87394":"Netgear",
    # ─── Broadcom ───
    "000AF5":"Broadcom","002275":"Broadcom","002655":"Broadcom",
    "20CF30":"Broadcom","68FB7E":"Broadcom","AC5F3E":"Broadcom",
    # ─── Google / Nest ───
    "001A11":"Google","080028":"Google","1C25BF":"Google",
    "200723":"Google","3C5AB4":"Google","442A60":"Google",
    "48D6D5":"Google","54609A":"Google","58B0D4":"Google",
    "5C6B4F":"Google","6C5C3D":"Google","7CFF4D":"Google",
    "940019":"Google","94EB2C":"Google","98D293":"Google",
    "A47014":"Google","D4F556":"Google","DCA632":"Google",
    "E4F0AB":"Google","F4F5E8":"Google","F4F5D8":"Google",
    "F88FCA":"Google",
    "18B430":"Nest","1861C7":"Nest","64167F":"Nest","6416F0":"Nest",
    "D813F8":"Nest",
    # ─── Amazon / Ring / Echo ───
    "001DCF":"Amazon","0C47C9":"Amazon","10CE35":"Amazon",
    "1CE2CC":"Amazon","2C0A3E":"Amazon","3483C7":"Amazon",
    "38F73D":"Amazon","40A2DB":"Amazon","440019":"Amazon",
    "4849C7":"Amazon","4CEFC0":"Amazon","5CF8A1":"Amazon",
    "687876":"Amazon","687E27":"Amazon","68541F":"Amazon",
    "6C5697":"Amazon","747548":"Amazon","7C6126":"Amazon",
    "84D611":"Amazon","889AEA":"Amazon","8C7499":"Amazon",
    "90A229":"Amazon","A002DC":"Amazon","A46C2E":"Amazon",
    "ACCE83":"Amazon","B47C9C":"Amazon","C0EE40":"Amazon",
    "CCF735":"Amazon","D82547":"Amazon","DC5483":"Amazon",
    "E0F5C6":"Amazon","F0272D":"Amazon","F0D2F1":"Amazon",
    "FC6510":"Amazon","FC65DE":"Amazon","FCA183":"Amazon",
    # ─── Microsoft / Xbox ───
    "000D3A":"Microsoft","0050F2":"Microsoft","001DD8":"Microsoft",
    "0024BE":"Microsoft","002722":"Microsoft","00226E":"Microsoft",
    "2816A8":"Microsoft","30592D":"Microsoft","3CDA2A":"Microsoft",
    "5CBA37":"Microsoft","60456B":"Microsoft","707974":"Microsoft",
    "7CB27D":"Microsoft","98522D":"Microsoft","B4AE2B":"Microsoft",
    "B83E59":"Microsoft","C83F26":"Microsoft","DC5360":"Microsoft",
    # ─── Realtek (chipsets WiFi comunes) ───
    "001569":"Realtek","001F1F":"Realtek","005A13":"Realtek",
    "0007E6":"Realtek","000B6B":"Realtek","00E04C":"Realtek",
    "08ED02":"Realtek","107B44":"Realtek","282CB2":"Realtek",
    "2C4D54":"Realtek","480FCF":"Realtek","485AB6":"Realtek",
    "508A42":"Realtek","5C12D9":"Realtek","7C10C9":"Realtek",
    "9CE95D":"Realtek","A81B5A":"Realtek","B05B67":"Realtek",
    "C82165":"Realtek","D46A6A":"Realtek","E0B6F5":"Realtek",
    "E04F43":"Realtek","E89120":"Realtek","F81A67":"Realtek",
    # ─── MediaTek / Ralink ───
    "000C43":"Ralink/MediaTek","000E8E":"Ralink/MediaTek",
    "00173F":"Ralink/MediaTek","0C4CC3":"MediaTek",
    "148A70":"MediaTek","240DC2":"MediaTek","38C1A4":"MediaTek",
    "408805":"MediaTek","4CE676":"MediaTek","78D294":"MediaTek",
    "8497D7":"MediaTek","ACD6B3":"MediaTek",
    # ─── Raspberry Pi / Espressif (IoT) ───
    "B827EB":"Raspberry Pi","DC2632":"Raspberry Pi","DCA632":"Raspberry Pi",
    "E45F01":"Raspberry Pi",
    "24A160":"Espressif","240AC4":"Espressif","246F28":"Espressif",
    "2C3AE8":"Espressif","30AEA4":"Espressif","3CE90E":"Espressif",
    "4C7525":"Espressif","5002A5":"Espressif","5CCF7F":"Espressif",
    "60019B":"Espressif","68C63A":"Espressif","7C9EBD":"Espressif",
    "840D8E":"Espressif","8C4B14":"Espressif","98CDAC":"Espressif",
    "9C9C1F":"Espressif","A0764E":"Espressif","A4CF12":"Espressif",
    "AC67B2":"Espressif","B4E62D":"Espressif","BC5E34":"Espressif",
    "BCDDC2":"Espressif","C44F33":"Espressif","C45BBE":"Espressif",
    "CC50E3":"Espressif","D8A01D":"Espressif","E0980C":"Espressif",
    "E8DB84":"Espressif","ECFABC":"Espressif","F008D1":"Espressif",
    "F4CFA2":"Espressif",
    # ─── Sony ───
    "001315":"Sony","001D28":"Sony","002345":"Sony","0024BE":"Sony",
    "001FA7":"Sony","002457":"Sony","009C02":"Sony","04FE31":"Sony",
    "10A5D0":"Sony","1C96E8":"Sony","244B03":"Sony","280DFC":"Sony",
    "2C3508":"Sony","3C0707":"Sony","442C05":"Sony","48F0E3":"Sony",
    "4CB9C8":"Sony","5C2F49":"Sony","701DC2":"Sony","70D4F2":"Sony",
    "78843C":"Sony","84241E":"Sony","94CE2C":"Sony","A8E3EE":"Sony",
    "B0C4E7":"Sony","FC0FE6":"Sony",
    # ─── LG Electronics ───
    "000AE7":"LG","000631":"LG","001C62":"LG","001E75":"LG",
    "001FE3":"LG","00219E":"LG","00266D":"LG","0022A9":"LG",
    "0026E2":"LG","002483":"LG","001FE3":"LG","10683F":"LG",
    "20210B":"LG","2CE2A8":"LG","3C2DB7":"LG","40B88B":"LG",
    "44CEB8":"LG","482265":"LG","500F80":"LG","5444A1":"LG",
    "58A2B2":"LG","60C1CB":"LG","64899A":"LG","6CD71E":"LG",
    "70F11C":"LG","78F882":"LG","88C9D0":"LG","8C3AE3":"LG",
    "901ACF":"LG","984827":"LG","9CD91D":"LG","A0F3C1":"LG",
    "A84E3F":"LG","AA0B46":"LG","B4E62D":"LG","B8D9CE":"LG",
    "C4438F":"LG","C449BB":"LG","C893E4":"LG","CC2D1B":"LG",
    "D8B377":"LG","D8A25E":"LG","F84241":"LG",
    # ─── Linksys / Belkin ───
    "000625":"Linksys","000C41":"Linksys","000E08":"Linksys",
    "000F66":"Linksys","001217":"Linksys","001310":"Linksys",
    "001839":"Linksys","0018F8":"Linksys","001A70":"Linksys",
    "001E58":"Linksys","002129":"Linksys","587B5D":"Linksys",
    "14D4FE":"Belkin","000102":"Belkin","001150":"Belkin",
    "0024E8":"Belkin","0030BD":"Belkin","08863B":"Belkin",
    "24F5A2":"Belkin","944452":"Belkin","B4750E":"Belkin",
    "C0562D":"Belkin","E8F1B0":"Belkin","EC1A59":"Belkin",
    # ─── ASUS ───
    "000C6E":"ASUS","000E7A":"ASUS","001731":"ASUS","001A92":"ASUS",
    "001E8C":"ASUS","002354":"ASUS","002618":"ASUS","049226":"ASUS",
    "08606E":"ASUS","0C9D92":"ASUS","107B44":"ASUS","1C872C":"ASUS",
    "1CB72C":"ASUS","200BC7":"ASUS","2C4D54":"ASUS","2CFDA1":"ASUS",
    "305A3A":"ASUS","3085A9":"ASUS","382C4A":"ASUS","40167E":"ASUS",
    "485B39":"ASUS","504E75":"ASUS","50465D":"ASUS","54A050":"ASUS",
    "60A44C":"ASUS","6045CB":"ASUS","6C724A":"ASUS","708BCD":"ASUS",
    "7824AF":"ASUS","88D7F6":"ASUS","8C882B":"ASUS","90E6BA":"ASUS",
    "9C5C8E":"ASUS","A85EF3":"ASUS","AC9E17":"ASUS","B06EBF":"ASUS",
    "BC5436":"ASUS","C0A5DD":"ASUS","C86000":"ASUS","D45D64":"ASUS",
    "D850E6":"ASUS","E03F49":"ASUS","E0CB4E":"ASUS","F07959":"ASUS",
    "F46D04":"ASUS","F80113":"ASUS",
    # ─── D-Link ───
    "000D88":"D-Link","000F3D":"D-Link","001195":"D-Link",
    "001346":"D-Link","001559":"D-Link","001B11":"D-Link",
    "001CF0":"D-Link","001E58":"D-Link","002191":"D-Link",
    "002401":"D-Link","002811":"D-Link","00CB51":"D-Link",
    "1062EB":"D-Link","143005":"D-Link","1C5F2B":"D-Link",
    "1CAFF7":"D-Link","1CBDB9":"D-Link","282CB2":"D-Link",
    "28107B":"D-Link","30B5C2":"D-Link","3400A3":"D-Link",
    "340804":"D-Link","34A84E":"D-Link","40F201":"D-Link",
    "5C4979":"D-Link","5CD998":"D-Link","6045BD":"D-Link",
    "78542E":"D-Link","788DF7":"D-Link","841B5E":"D-Link",
    "84C9B2":"D-Link","908D78":"D-Link","9094E4":"D-Link",
    "90D7BE":"D-Link","A0AB1B":"D-Link","ACF1DF":"D-Link",
    "B4A5EF":"D-Link","B8A386":"D-Link","BCF685":"D-Link",
    "C0A0BB":"D-Link","C412F5":"D-Link","C4A81D":"D-Link",
    "C8BE19":"D-Link","C8D3A3":"D-Link","CCB255":"D-Link",
    "D86CE9":"D-Link","D88A3B":"D-Link","E01CF0":"D-Link",
    "E46F13":"D-Link","E8CC18":"D-Link","F07D68":"D-Link",
    "F0B4D2":"D-Link","F485C6":"D-Link","FC7516":"D-Link",
    # ─── Motorola / Lenovo ───
    "001404":"Motorola","001A1E":"Motorola","00A0BF":"Motorola",
    "04F8C9":"Motorola","24DA9B":"Motorola","3C6AA7":"Motorola",
    "40786A":"Motorola","6CB70D":"Motorola","745C4B":"Motorola",
    "80B99E":"Motorola","84100D":"Motorola","840B2D":"Motorola",
    "9C0217":"Motorola","CC61E5":"Motorola","E4907E":"Motorola",
    "F83441":"Motorola","F8CFE2":"Motorola","FCC23D":"Motorola",
    "001E68":"Lenovo","002315":"Lenovo","003010":"Lenovo",
    "006057":"Lenovo","00D861":"Lenovo","28D24F":"Lenovo",
    "408F52":"Lenovo","441CA8":"Lenovo","50326B":"Lenovo",
    "54E1AD":"Lenovo","5CF3FC":"Lenovo","600292":"Lenovo",
    "7C7A91":"Lenovo","849CA6":"Lenovo","8C8CAA":"Lenovo",
    "985FD3":"Lenovo","B0FCBb":"Lenovo","C0B9C1":"Lenovo",
    "C83870":"Lenovo","CC52AF":"Lenovo","E8E0B7":"Lenovo",
    "F0DEFE":"Lenovo",
    # ─── Dell / HP ───
    "001422":"Dell","001C23":"Dell","001E4F":"Dell","002219":"Dell",
    "00268B":"Dell","0C29EF":"Dell","143E60":"Dell","14187D":"Dell",
    "184617":"Dell","1C4024":"Dell","24B6FD":"Dell","28F10E":"Dell",
    "34175D":"Dell","34E6AD":"Dell","54BF64":"Dell","5C260A":"Dell",
    "645A04":"Dell","782BCA":"Dell","803773":"Dell","848F69":"Dell",
    "90B11C":"Dell","98903B":"Dell","A44CC8":"Dell","B0357F":"Dell",
    "B82A72":"Dell","BC3090":"Dell","C81F66":"Dell","D067E5":"Dell",
    "D09466":"Dell","D481D7":"Dell","D894E3":"Dell","D89695":"Dell",
    "E0071B":"Dell","E4434B":"Dell","E4F0AB":"Dell","F04DA2":"Dell",
    "F0D4E2":"Dell","F48E38":"Dell","F8BC12":"Dell","F8CAB8":"Dell",
    "000802":"HP","00E01E":"HP","001083":"HP","001185":"HP",
    "001279":"HP","001321":"HP","001635":"HP","001708":"HP",
    "001871":"HP","001A4B":"HP","001B78":"HP","001CC4":"HP",
    "001E0B":"HP","001F29":"HP","002151":"HP","002314":"HP",
    "002481":"HP","002655":"HP","0030C1":"HP","0A0027":"HP",
    "10604B":"HP","10E7C6":"HP","145254":"HP","187ED5":"HP",
    "1CC1DE":"HP","2C233A":"HP","2C27D7":"HP","2C412E":"HP",
    "2C44FD":"HP","2C768A":"HP","30E171":"HP","30E37A":"HP",
    "3464A9":"HP","389D92":"HP","3CA82A":"HP","40A8F0":"HP",
    "44481E":"HP","4C3975":"HP","5065F3":"HP","50ED3C":"HP",
    "5C8A38":"HP","603717":"HP","60F6FD":"HP","6453D0":"HP",
    "64510F":"HP","6CC217":"HP","703ACA":"HP","70106F":"HP",
    "7C4AA8":"HP","80A589":"HP","80CE62":"HP","84345C":"HP",
    "843497":"HP","881DFC":"HP","8C99E6":"HP","984BE1":"HP",
    "98E7F4":"HP","A04025":"HP","A0481C":"HP","A0B3CC":"HP",
    "A0D3C1":"HP","A45D36":"HP","A85840":"HP","AC162D":"HP",
    "B07D64":"HP","B499BA":"HP","B4B676":"HP","B88A60":"HP",
    "C0BFC0":"HP","C48508":"HP","CC3E5F":"HP","D07E28":"HP",
    "D42C44":"HP","D4C10F":"HP","D4C9EF":"HP","D89D67":"HP",
    "E4115B":"HP","E8F724":"HP","EC8EB5":"HP","F05ACD":"HP",
    "F092B4":"HP","F0921C":"HP","F430B9":"HP","FC15B4":"HP",
    # ─── Aruba / Ubiquiti ───
    "000B86":"Aruba","001A1E":"Aruba","002083":"Aruba",
    "24DE80":"Aruba","40E3D6":"Aruba","6C8BD5":"Aruba",
    "842B2B":"Aruba","8C8CEA":"Aruba","940081":"Aruba",
    "9C1C12":"Aruba","A8BD27":"Aruba","B45D50":"Aruba",
    "D8C7C8":"Aruba","F0D1A9":"Aruba",
    "002722":"Ubiquiti","04D590":"Ubiquiti","0418D6":"Ubiquiti",
    "18E829":"Ubiquiti","1CF66E":"Ubiquiti","245A4C":"Ubiquiti",
    "249A1D":"Ubiquiti","24A43C":"Ubiquiti","287FE0":"Ubiquiti",
    "3408BC":"Ubiquiti","445101":"Ubiquiti","44D9E7":"Ubiquiti",
    "602229":"Ubiquiti","682B4A":"Ubiquiti","6870C6":"Ubiquiti",
    "688AB6":"Ubiquiti","749D79":"Ubiquiti","780044":"Ubiquiti",
    "788A20":"Ubiquiti","80220E":"Ubiquiti","802AA8":"Ubiquiti",
    "94E6F7":"Ubiquiti","9C05D6":"Ubiquiti","A4ED43":"Ubiquiti",
    "B4FBE4":"Ubiquiti","C4411E":"Ubiquiti","D021F9":"Ubiquiti",
    "D42C44":"Ubiquiti","DC9FDB":"Ubiquiti","E063DA":"Ubiquiti",
    "F09FC2":"Ubiquiti","F492BF":"Ubiquiti","F4E2CE":"Ubiquiti",
    "FCECDA":"Ubiquiti",
}

# ── BASE OUI ONLINE (IEEE) ────────────────────────────────────────────────────

OUI_URLS = [
    "https://standards-oui.ieee.org/oui/oui.txt",
    "http://standards-oui.ieee.org/oui/oui.txt",
]
OUI_CACHE = os.path.expanduser("~/.wifi_scanner_oui.json")
OUI_MAX_AGE_DAYS = 30


def download_oui_ieee():
    """Descarga la base completa de IEEE (~30k+ vendors)."""
    import urllib.request
    vendors = {}
    for url in OUI_URLS:
        try:
            print(f"{CYAN}[*] Descargando OUI desde {url}...{RESET}")
            req = urllib.request.Request(url, headers={"User-Agent": "WiFiScanner/2.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read().decode("utf-8", errors="ignore")
            for line in data.splitlines():
                m = re.match(
                    r"^\s*([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)",
                    line,
                )
                if m:
                    oui = m.group(1).upper().replace("-", "")
                    vendors[oui] = m.group(2).strip()
            if vendors:
                # Guardar caché
                cache = {"ts": datetime.datetime.now().isoformat(), "vendors": vendors}
                try:
                    with open(OUI_CACHE, "w") as f:
                        json.dump(cache, f)
                    print(f"{GREEN}[+] {len(vendors)} vendors descargados y cacheados en {OUI_CACHE}{RESET}")
                except Exception as e:
                    print(f"{YELLOW}[!] No se pudo guardar caché: {e}{RESET}")
                return vendors
        except Exception as e:
            print(f"{YELLOW}[!] Error descargando {url}: {e}{RESET}")
    return {}


def load_oui_cache():
    """Carga OUI desde caché local si es reciente."""
    if not os.path.exists(OUI_CACHE):
        return {}
    try:
        with open(OUI_CACHE, "r") as f:
            cache = json.load(f)
        ts = datetime.datetime.fromisoformat(cache["ts"])
        age = (datetime.datetime.now() - ts).days
        if age > OUI_MAX_AGE_DAYS:
            print(f"{YELLOW}[!] Caché OUI vencida ({age} días). Se intentará descargar nueva.{RESET}")
            return {}
        vendors = cache.get("vendors", {})
        print(f"{GREEN}[+] OUI caché cargada: {len(vendors)} vendors (edad: {age} días){RESET}")
        return vendors
    except Exception:
        return {}


def load_oui_file(path):
    """Carga OUI desde un archivo local (JSON, CSV, o formato IEEE)."""
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    # Intentar JSON
    try:
        data = json.loads(content)
        return {k.upper().replace(":", "").replace("-", ""): v for k, v in data.items()}
    except json.JSONDecodeError:
        pass
    # Parsear IEEE / CSV
    vendors = {}
    for line in content.splitlines():
        m = re.match(
            r"^\s*([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)",
            line,
        )
        if m:
            vendors[m.group(1).upper().replace("-", "").replace(":", "")] = m.group(2).strip()
            continue
        m = re.match(
            r"^([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})[,\t ]+(.+)", line
        )
        if m:
            vendors[m.group(1).upper().replace("-", "").replace(":", "")] = m.group(2).strip()
    return vendors


def build_vendor_db(oui_file=None, force_download=False):
    """
    Construye la base de vendors con prioridad:
    1. Base embebida (siempre disponible)
    2. Archivo OUI local (si se proporcionó)
    3. Caché descargada
    4. Descarga nueva de IEEE (si hay internet y caché expiró)
    """
    db = dict(EMBEDDED_OUI)
    print(f"{CYAN}[*] Base embebida: {len(db)} vendors{RESET}")

    # Archivo local
    if oui_file:
        local = load_oui_file(oui_file)
        if local:
            db.update(local)
            print(f"{GREEN}[+] Archivo OUI local: +{len(local)} vendors{RESET}")

    # Caché o descarga
    if force_download:
        online = download_oui_ieee()
        if online:
            db.update(online)
    else:
        cached = load_oui_cache()
        if cached:
            db.update(cached)
        else:
            # Intentar descargar
            online = download_oui_ieee()
            if online:
                db.update(online)
            else:
                print(f"{YELLOW}[!] Sin conexión, usando solo base embebida{RESET}")

    print(f"{GREEN}[+] Base total: {len(db)} vendors{RESET}")
    return db


def get_vendor(mac, vendors):
    if not mac:
        return "Desconocido"
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    return vendors.get(oui, "Desconocido")


# ── INTERFAZ WIFI ─────────────────────────────────────────────────────────────


def get_interface():
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE,TYPE", "device"],
            capture_output=True, text=True,
        )
        for line in r.stdout.splitlines():
            p = line.split(":")
            if len(p) >= 2 and p[1].strip() == "wifi":
                return p[0].strip()
    except Exception:
        pass
    try:
        for iface in os.listdir("/sys/class/net"):
            if os.path.exists(f"/sys/class/net/{iface}/wireless"):
                return iface
    except Exception:
        pass
    return "wlan0"


def get_monitor_interface():
    """Busca una interfaz en modo monitor (mon0, wlan0mon, etc.)."""
    try:
        for iface in os.listdir("/sys/class/net"):
            # Verificar si está en modo monitor
            try:
                r = subprocess.run(
                    ["iwconfig", iface],
                    capture_output=True, text=True, timeout=5,
                )
                if "Mode:Monitor" in r.stdout:
                    return iface
            except Exception:
                continue
    except Exception:
        pass
    return None


def enable_monitor_mode(iface):
    """Intenta poner la interfaz en modo monitor."""
    mon_iface = f"{iface}mon"
    try:
        # Método airmon-ng
        print(f"{CYAN}[*] Activando modo monitor con airmon-ng...{RESET}")
        subprocess.run(["airmon-ng", "check", "kill"], capture_output=True, timeout=10)
        r = subprocess.run(
            ["airmon-ng", "start", iface],
            capture_output=True, text=True, timeout=15,
        )
        # Buscar el nombre de la interfaz monitor
        m = re.search(r"(\w+mon\w*)", r.stdout)
        if m:
            mon_iface = m.group(1)
        # Verificar que existe
        if os.path.exists(f"/sys/class/net/{mon_iface}"):
            print(f"{GREEN}[+] Modo monitor activo: {mon_iface}{RESET}")
            return mon_iface
        # Probar con el nombre original + mon
        for candidate in [f"{iface}mon", "mon0", iface]:
            if os.path.exists(f"/sys/class/net/{candidate}"):
                return candidate
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"{YELLOW}[!] airmon-ng falló: {e}{RESET}")

    try:
        # Método manual
        print(f"{CYAN}[*] Activando modo monitor manualmente...{RESET}")
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)
        r = subprocess.run(["iwconfig", iface], capture_output=True, text=True, timeout=5)
        if "Mode:Monitor" in r.stdout:
            print(f"{GREEN}[+] Modo monitor activo: {iface}{RESET}")
            return iface
    except Exception as e:
        print(f"{YELLOW}[!] Método manual falló: {e}{RESET}")

    return None


def disable_monitor_mode(iface):
    """Restaura la interfaz a modo managed."""
    try:
        base_iface = iface.replace("mon", "")
        subprocess.run(["airmon-ng", "stop", iface], capture_output=True, timeout=10)
        subprocess.run(["systemctl", "restart", "NetworkManager"], capture_output=True, timeout=10)
        print(f"{CYAN}[*] Modo monitor desactivado{RESET}")
    except Exception:
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", iface, "set", "type", "managed"], capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)
            subprocess.run(["systemctl", "restart", "NetworkManager"], capture_output=True, timeout=10)
        except Exception:
            pass


# ── SEÑAL HELPERS ─────────────────────────────────────────────────────────────


def dbm_to_pct(dbm):
    try:
        d = int(dbm)
        if d <= -100:
            return 0
        if d >= -50:
            return 100
        return 2 * (d + 100)
    except (ValueError, TypeError):
        return 0


def signal_bar(pct, width=15):
    """Genera barra visual de señal."""
    filled = int(pct / 100 * width)
    if pct >= 70:
        color = GREEN
    elif pct >= 40:
        color = YELLOW
    else:
        color = RED
    return f"{color}{'█' * filled}{DIM}{'░' * (width - filled)}{RESET}"


def parse_security(s):
    s = s.strip().upper()
    if not s or s == "--":
        return {"label": "ABIERTA", "level": "critical", "detail": "Sin cifrado"}
    if "WPA3" in s:
        return {"label": "WPA3", "level": "safe", "detail": s}
    if "WPA2" in s:
        return {"label": "WPA2", "level": "safe", "detail": s}
    if "WPA" in s:
        return {"label": "WPA", "level": "warning", "detail": s}
    if "WEP" in s:
        return {"label": "WEP", "level": "danger", "detail": "Cifrado obsoleto"}
    return {"label": s or "?", "level": "unknown", "detail": s}


# ── ESCANEO DE REDES (APs) ───────────────────────────────────────────────────


def rescan(iface):
    try:
        subprocess.run(
            ["nmcli", "device", "wifi", "rescan", "ifname", iface],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass


def scan_nmcli(iface):
    r = subprocess.run(
        [
            "nmcli", "-t", "-f",
            "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY",
            "device", "wifi", "list", "ifname", iface,
        ],
        capture_output=True, text=True, timeout=20,
    )
    networks, seen = [], set()
    for line in r.stdout.splitlines():
        m = re.match(
            r"^(.*?):([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:"
            r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}):(.*)$",
            line,
        )
        if not m:
            continue
        ssid, bssid = m.group(1).strip() or "<OCULTO>", m.group(2).upper()
        if bssid in seen:
            continue
        seen.add(bssid)
        rest = m.group(3).split(":")
        sig = rest[4] if len(rest) > 4 else "0"
        sec = ":".join(rest[5:]) if len(rest) > 5 else ""
        networks.append({
            "ssid": ssid,
            "bssid": bssid,
            "channel": rest[1] if len(rest) > 1 else "",
            "freq": rest[2] if len(rest) > 2 else "",
            "rate": rest[3] if len(rest) > 3 else "",
            "signal_dbm": sig,
            "signal_pct": dbm_to_pct(sig),
            "security_raw": sec,
            "security": parse_security(sec),
            "clients": [],
        })
    return networks


def scan_iwlist(iface):
    r = subprocess.run(
        ["iwlist", iface, "scanning"],
        capture_output=True, text=True, timeout=20,
    )
    networks, seen, cur = [], set(), {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if "Cell " in line and "Address:" in line:
            if cur and cur.get("bssid") not in seen:
                seen.add(cur.get("bssid", ""))
                networks.append(cur)
            bssid = re.search(r"Address: ([0-9A-F:]{17})", line)
            cur = {"bssid": bssid.group(1) if bssid else "??", "ssid": "<OCULTO>", "clients": []}
        elif line.startswith("ESSID:"):
            m = re.search(r'ESSID:"(.*)"', line)
            cur["ssid"] = m.group(1) if m else "<OCULTO>"
        elif "Frequency:" in line:
            f = re.search(r"Frequency:([\d.]+ \w+)", line)
            cur["freq"] = f.group(1) if f else ""
            c = re.search(r"Channel (\d+)", line)
            cur["channel"] = c.group(1) if c else ""
        elif "Quality=" in line:
            s = re.search(r"Signal level=(-?\d+)", line)
            dbm = s.group(1) if s else "0"
            cur["signal_dbm"] = dbm
            cur["signal_pct"] = dbm_to_pct(dbm)
        elif "Encryption key:" in line:
            cur["_enc"] = "on" in line.lower()
        elif "WPA2" in line.upper():
            cur["security_raw"] = "WPA2"
        elif "WPA" in line.upper():
            cur.setdefault("security_raw", "WPA")
    if cur and cur.get("bssid") not in seen:
        networks.append(cur)
    for n in networks:
        n.setdefault("security_raw", "WEP" if n.get("_enc") else "")
        n["security"] = parse_security(n.get("security_raw", ""))
        for k in ("channel", "freq", "rate", "signal_dbm"):
            n.setdefault(k, "")
        n.setdefault("signal_pct", 0)
    return networks


def scan_networks(iface):
    """Escanea redes WiFi (APs)."""
    print(f"{CYAN}[*] Escaneando APs en {iface}...{RESET}")
    rescan(iface)
    try:
        subprocess.run(["nmcli", "--version"], capture_output=True, check=True)
        nets = scan_nmcli(iface)
        if nets:
            return nets
    except Exception:
        pass
    print(f"{YELLOW}[!] Fallback a iwlist...{RESET}")
    return scan_iwlist(iface)


# ── ESCANEO DE CLIENTES ──────────────────────────────────────────────────────


def scan_clients_airodump(mon_iface, duration=15):
    """
    Escanea clientes WiFi usando airodump-ng.
    Retorna dict: {bssid_ap: [{mac, signal_dbm, signal_pct, probes}]}
    """
    tmpdir = "/tmp/wifi_scanner_airodump"
    os.makedirs(tmpdir, exist_ok=True)
    prefix = f"{tmpdir}/scan"

    # Limpiar archivos previos
    for f in os.listdir(tmpdir):
        os.remove(os.path.join(tmpdir, f))

    clients_by_ap = {}

    try:
        print(f"{CYAN}[*] Capturando tráfico ({duration}s) en {mon_iface}...{RESET}")
        proc = subprocess.Popen(
            [
                "airodump-ng",
                "--write", prefix,
                "--write-interval", "1",
                "--output-format", "csv",
                mon_iface,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        # Parsear CSV de airodump
        csv_file = f"{prefix}-01.csv"
        if not os.path.exists(csv_file):
            # Buscar cualquier CSV generado
            for f in sorted(os.listdir(tmpdir)):
                if f.endswith(".csv"):
                    csv_file = os.path.join(tmpdir, f)
                    break

        if os.path.exists(csv_file):
            with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # La sección de clientes viene después de la segunda cabecera
            sections = re.split(r"\n\s*\n", content)
            client_section = None
            for section in sections:
                if "Station MAC" in section:
                    client_section = section
                    break

            if client_section:
                lines = client_section.strip().splitlines()
                for line in lines[1:]:  # Skip header
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 6:
                        client_mac = parts[0].upper()
                        if not re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", client_mac):
                            continue
                        ap_bssid = parts[5].strip().upper() if len(parts) > 5 else ""
                        signal = parts[3].strip() if len(parts) > 3 else ""
                        probes = parts[-1].strip() if len(parts) > 6 else ""

                        client = {
                            "mac": client_mac,
                            "signal_dbm": signal,
                            "signal_pct": dbm_to_pct(signal),
                            "probes": probes,
                        }

                        if ap_bssid and ap_bssid != "(NOT ASSOCIATED)":
                            if ap_bssid not in clients_by_ap:
                                clients_by_ap[ap_bssid] = []
                            clients_by_ap[ap_bssid].append(client)
                        else:
                            # Clientes no asociados
                            if "__UNASSOCIATED__" not in clients_by_ap:
                                clients_by_ap["__UNASSOCIATED__"] = []
                            clients_by_ap["__UNASSOCIATED__"].append(client)

    except FileNotFoundError:
        print(f"{RED}[✗] airodump-ng no encontrado. Instalá aircrack-ng:{RESET}")
        print(f"    sudo apt install aircrack-ng")
        return {}
    except Exception as e:
        print(f"{RED}[✗] Error en airodump: {e}{RESET}")
        return {}
    finally:
        # Limpiar
        for f in os.listdir(tmpdir):
            try:
                os.remove(os.path.join(tmpdir, f))
            except Exception:
                pass

    total = sum(len(v) for v in clients_by_ap.values())
    print(f"{GREEN}[+] {total} clientes detectados{RESET}")
    return clients_by_ap


def scan_clients_iw(iface):
    """
    Escaneo de clientes usando iw (solo muestra los de la red actual).
    Fallback cuando no hay modo monitor.
    """
    clients_by_ap = {}
    try:
        # Obtener BSSID del AP actual
        r = subprocess.run(
            ["iw", "dev", iface, "link"],
            capture_output=True, text=True, timeout=10,
        )
        bssid_m = re.search(r"Connected to ([0-9a-fA-F:]{17})", r.stdout)
        if not bssid_m:
            return {}
        current_bssid = bssid_m.group(1).upper()

        # Escaneo ARP - vecinos en la misma red
        r = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=10,
        )
        clients = []
        for line in r.stdout.splitlines():
            m = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]{17})",
                line,
            )
            if m:
                mac = m.group(2).upper()
                if mac != "FF:FF:FF:FF:FF:FF" and not mac.startswith("33:33:"):
                    clients.append({
                        "mac": mac,
                        "signal_dbm": "N/A",
                        "signal_pct": 0,
                        "probes": "",
                        "ip": m.group(1),
                    })

        if clients:
            clients_by_ap[current_bssid] = clients
            print(f"{GREEN}[+] {len(clients)} vecinos ARP detectados en red actual{RESET}")

    except Exception as e:
        print(f"{YELLOW}[!] Error en escaneo ARP: {e}{RESET}")

    return clients_by_ap


# ── WHITELIST ─────────────────────────────────────────────────────────────────


def load_whitelist(path):
    if not path or not os.path.exists(path):
        return set()
    with open(path) as f:
        return {l.strip().upper() for l in f if l.strip() and not l.startswith("#")}


def whitelisted(n, wl):
    if not wl:
        return True
    return n.get("ssid", "").upper() in wl or n.get("bssid", "").upper() in wl


# ── TERMINAL OUTPUT ───────────────────────────────────────────────────────────


def print_report(networks, wl, vendors, show_clients=False):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    W = 120

    # Header
    print(f"\n{BOLD}{CYAN}{'═' * W}{RESET}")
    print(f"{BOLD}{CYAN}  📡 WiFi Environment Scanner v2.0 — {ts}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * W}{RESET}")

    # Stats
    total = len(networks)
    open_nets = sum(1 for n in networks if n["security"]["level"] == "critical")
    wep_nets = sum(1 for n in networks if n["security"]["level"] == "danger")
    unauth = sum(1 for n in networks if not whitelisted(n, wl)) if wl else 0
    total_clients = sum(len(n.get("clients", [])) for n in networks)

    print(f"\n  {BOLD}Redes:{RESET} {total}  │  "
          f"{GREEN}Seguras:{RESET} {total - open_nets - wep_nets}  │  "
          f"{RED}Abiertas:{RESET} {open_nets}  │  "
          f"{YELLOW}WEP:{RESET} {wep_nets}  │  "
          f"{RED}No autorizadas:{RESET} {unauth}  │  "
          f"{CYAN}Clientes:{RESET} {total_clients}")
    print()

    # Table header
    print(f"  {DIM}{'─' * (W - 4)}{RESET}")
    hdr = (
        f"  {BOLD}{'SSID':<25} {'BSSID':<19} {'CH':>3}  "
        f"{'SEÑAL':>6}  {'':>15}  {'CIFRADO':<8}  {'VENDOR':<22}  "
        f"{'CLI':>3}  ESTADO{RESET}"
    )
    print(hdr)
    print(f"  {DIM}{'─' * (W - 4)}{RESET}")

    alerts = []
    for n in sorted(networks, key=lambda x: -x.get("signal_pct", 0)):
        ssid = n["ssid"][:24]
        bssid = n["bssid"]
        chan = n.get("channel", "?")
        pct = n["signal_pct"]
        dbm = n["signal_dbm"]
        sec = n["security"]
        vendor = get_vendor(bssid, vendors)[:21]
        ok = whitelisted(n, wl)
        num_clients = len(n.get("clients", []))

        # Estado
        if not ok:
            estado = f"{RED}⚠ NO AUTORIZADA{RESET}"
            alerts.append(n)
        elif sec["level"] == "critical":
            estado = f"{RED}⚠ ABIERTA{RESET}"
            alerts.append(n)
        elif sec["level"] == "danger":
            estado = f"{YELLOW}⚠ WEP{RESET}"
            alerts.append(n)
        elif sec["level"] == "warning":
            estado = f"{YELLOW}~ WPA{RESET}"
        else:
            estado = f"{GREEN}✓ OK{RESET}"

        # Color cifrado
        sec_colors = {
            "critical": RED, "danger": RED,
            "warning": YELLOW, "safe": GREEN,
        }
        sc = sec_colors.get(sec["level"], DIM)

        bar = signal_bar(pct)

        print(
            f"  {ssid:<25} {DIM}{bssid}{RESET} {chan:>3}  "
            f"{pct:>4}%  {bar}  "
            f"{sc}{sec['label']:<8}{RESET}  {vendor:<22}  "
            f"{CYAN}{num_clients:>3}{RESET}  {estado}"
        )

        # Mostrar clientes debajo si corresponde
        if show_clients and n.get("clients"):
            for client in n["clients"]:
                cmac = client["mac"]
                cvendor = get_vendor(cmac, vendors)[:20]
                csig = client.get("signal_dbm", "N/A")
                cpct = client.get("signal_pct", 0)
                cbar = signal_bar(cpct, width=8) if isinstance(cpct, int) and cpct > 0 else f"{DIM}{'░' * 8}{RESET}"
                cip = client.get("ip", "")
                probes = client.get("probes", "")

                extra = ""
                if cip:
                    extra += f" {DIM}IP:{cip}{RESET}"
                if probes:
                    extra += f" {DIM}Probes:{probes}{RESET}"

                print(
                    f"    {DIM}└─{RESET} {MAGENTA}{cmac}{RESET}  "
                    f"{csig:>5}dBm {cbar}  "
                    f"{cvendor:<20}{extra}"
                )

    # Footer
    print(f"  {DIM}{'─' * (W - 4)}{RESET}")
    print(f"  Total: {BOLD}{len(networks)}{RESET} redes, {BOLD}{total_clients}{RESET} clientes")

    # Alertas
    if alerts:
        print(f"\n  {RED}{BOLD}⚠ ALERTAS ({len(alerts)}):{RESET}")
        for a in alerts:
            if not whitelisted(a, wl):
                reason = "No en whitelist"
            else:
                reason = a["security"]["detail"]
            print(f"    {RED}→ {a['ssid']} [{a['bssid']}] — {reason}{RESET}")

    # Unassociated clients
    unassoc = [n for n in networks if n.get("ssid") == "__UNASSOCIATED__"]
    if unassoc:
        print(f"\n  {MAGENTA}{BOLD}📱 Clientes no asociados (buscando red):{RESET}")
        for client in unassoc[0].get("clients", []):
            cmac = client["mac"]
            cvendor = get_vendor(cmac, vendors)[:25]
            probes = client.get("probes", "")
            print(f"    {MAGENTA}→ {cmac}  {cvendor}  {DIM}Probes: {probes or 'N/A'}{RESET}")

    print()


# ── MAIN ──────────────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(
        description="WiFi Environment Scanner v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 wifi_scanner.py                        # Escaneo básico
  sudo python3 wifi_scanner.py --clients              # Incluir clientes WiFi
  sudo python3 wifi_scanner.py --clients --duration 30 # Captura de 30s
  sudo python3 wifi_scanner.py --whitelist red.txt     # Verificar redes autorizadas
  sudo python3 wifi_scanner.py --update-oui            # Forzar descarga OUI
  sudo python3 wifi_scanner.py --rescan 60             # Re-escanear cada 60s
  sudo python3 wifi_scanner.py --json salida.json      # Exportar JSON
        """,
    )
    ap.add_argument("--interface", "-i", help="Interfaz WiFi a usar")
    ap.add_argument("--whitelist", "-w", help="Archivo whitelist (SSID/BSSID, uno por línea)")
    ap.add_argument("--oui-file", help="Archivo OUI local (JSON, CSV, formato IEEE)")
    ap.add_argument("--update-oui", action="store_true", help="Forzar descarga de base OUI IEEE")
    ap.add_argument("--clients", "-c", action="store_true", help="Escanear clientes WiFi (MACs)")
    ap.add_argument("--duration", "-d", type=int, default=15, help="Duración captura clientes (segundos, default: 15)")
    ap.add_argument("--json", help="Exportar resultados a JSON")
    ap.add_argument("--rescan", "-r", type=int, default=0, help="Re-escanear cada N segundos (0 = una vez)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print(f"{YELLOW}[!] Recomendado ejecutar como root para resultados completos.{RESET}")

    # Vendor DB
    vendors = build_vendor_db(oui_file=args.oui_file, force_download=args.update_oui)

    # Interfaz
    iface = args.interface or get_interface()
    wl = load_whitelist(args.whitelist)
    if wl:
        print(f"{CYAN}[*] Whitelist: {len(wl)} entradas{RESET}")

    # Monitor mode si se piden clientes
    mon_iface = None
    monitor_enabled_by_us = False
    if args.clients:
        mon_iface = get_monitor_interface()
        if not mon_iface:
            print(f"{YELLOW}[!] No se encontró interfaz en modo monitor.{RESET}")
            mon_iface = enable_monitor_mode(iface)
            if mon_iface:
                monitor_enabled_by_us = True
            else:
                print(f"{YELLOW}[!] No se pudo activar modo monitor. "
                      f"Se usará escaneo ARP (limitado a red local).{RESET}")

    def cleanup():
        if monitor_enabled_by_us and mon_iface:
            print(f"\n{CYAN}[*] Restaurando interfaz...{RESET}")
            disable_monitor_mode(mon_iface)

    signal.signal(signal.SIGINT, lambda s, f: (cleanup(), sys.exit(0)))

    def run():
        # Escanear APs
        nets = scan_networks(iface)
        if not nets:
            print(f"{YELLOW}[!] Sin resultados. Verificá que la interfaz esté activa.{RESET}")
            return

        # Escanear clientes
        if args.clients:
            if mon_iface:
                clients_map = scan_clients_airodump(mon_iface, duration=args.duration)
            else:
                clients_map = scan_clients_iw(iface)

            # Asociar clientes a sus APs
            for net in nets:
                bssid = net["bssid"]
                net["clients"] = clients_map.get(bssid, [])

            # Agregar no-asociados como red virtual
            if "__UNASSOCIATED__" in clients_map:
                nets.append({
                    "ssid": "__UNASSOCIATED__",
                    "bssid": "FF:FF:FF:FF:FF:FF",
                    "channel": "-",
                    "freq": "",
                    "rate": "",
                    "signal_dbm": "0",
                    "signal_pct": 0,
                    "security_raw": "",
                    "security": {"label": "-", "level": "unknown", "detail": ""},
                    "clients": clients_map["__UNASSOCIATED__"],
                })

        # Mostrar
        print_report(nets, wl, vendors, show_clients=args.clients)

        # Exportar JSON
        if args.json:
            export = []
            for n in nets:
                entry = dict(n)
                entry["vendor"] = get_vendor(n["bssid"], vendors)
                entry["whitelisted"] = whitelisted(n, wl)
                for c in entry.get("clients", []):
                    c["vendor"] = get_vendor(c["mac"], vendors)
                export.append(entry)
            with open(args.json, "w") as f:
                json.dump(export, f, indent=2, ensure_ascii=False)
            print(f"{GREEN}[+] JSON → {args.json}{RESET}")

    try:
        if args.rescan > 0:
            print(f"{CYAN}[*] Modo continuo cada {args.rescan}s — Ctrl+C para salir{RESET}")
            while True:
                run()
                time.sleep(args.rescan)
        else:
            run()
    except KeyboardInterrupt:
        print(f"\n{CYAN}[*] Detenido.{RESET}")
    finally:
        cleanup()


if __name__ == "__main__":
    main()
