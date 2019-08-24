rule dns_threat_detection
{
	meta:
		author = "ionstorm"
		type = "Microsoft-Windows-DNS-Client"
		description = "Broad match; any request that matches string"
	strings:
		$s2 = /DNS\squery\sis\scompleted.+dlinkddns\.com/ ascii wide nocase
		$s3 = /DNS\squery\sis\scompleted.+no-ip\.com/ ascii wide nocase
		$s4 = /DNS\squery\sis\scompleted.+no-ip\.org/ ascii wide nocase
		$s5 = /DNS\squery\sis\scompleted.+no-ip\.biz/ ascii wide nocase
		$s6 = /DNS\squery\sis\scompleted.+no-ip\.info/ ascii wide nocase
		$s7 = /DNS\squery\sis\scompleted.+noip\.com/ ascii wide nocase
		$s8 = /DNS\squery\sis\scompleted.+afraid\.org/ ascii wide nocase
		$s9 = /DNS\squery\sis\scompleted.+duckdns\.org/ ascii wide nocase
		$s10 = /DNS\squery\sis\scompleted.+changeip\.com/ ascii wide nocase
		$s11 = /DNS\squery\sis\scompleted.+ddns\.net/ ascii wide nocase
		$s12 = /DNS\squery\sis\scompleted.+hopto\.org/ ascii wide nocase
		$s13 = /DNS\squery\sis\scompleted.+zapto\.org/ ascii wide nocase
		$s14 = /DNS\squery\sis\scompleted.+servehttp\.com/ ascii wide nocase
		$s15 = /DNS\squery\sis\scompleted.+sytes\.net/ ascii wide nocase
		$s16 = /DNS\squery\sis\scompleted.+whoer\.net/ ascii wide nocase
		$s17 = /DNS\squery\sis\scompleted.+bravica\.net/ ascii wide nocase
		$s18 = /DNS\squery\sis\scompleted.+ip.webmasterhome\.cn/ ascii wide nocase
		$s19 = /DNS\squery\sis\scompleted.+whatsmyip\.us/ ascii wide nocase
		$s20 = /DNS\squery\sis\scompleted.+myip\.kz/ ascii wide nocase
		$s21 = /DNS\squery\sis\scompleted.+ip-addr\.es/ ascii wide nocase
		$s22 = "curlmyip" ascii wide nocase

	condition:
		any of ($s*)
}
