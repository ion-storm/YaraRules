rule github_Broad
{
	meta:
		author = "b33f"
		type = "Microsoft-Windows-DNS-Client"
		description = "Broad match; any request that matches string"
	strings:
		$s = "github" ascii wide nocase

	condition:
		$s
}
