rule Blackhat_Broad
{
	meta:
		author = "b33f"
		type = "Microsoft-Windows-DNS-Client"
		description = "Broad match; any request that matches string"
	strings:
		$s = "blackhat.com" ascii wide nocase

	condition:
		$s
}
