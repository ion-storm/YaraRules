rule dns_testing
{
    meta:
      author = "ionstorm"
      type = "Microsoft-Windows-DNS-Client"
      description = "better dns parser"

    strings:
      $a = "DNS query is completed for the name" ascii wide nocase
      $s0 = "msn.com" ascii wide nocase
      $s1 = "aol.com" ascii wide nocase
      $s2 = "verge.com" ascii wide nocase
      $s3 = "microsoft.com" ascii wide nocase
      $s4 = "yahoo.com" ascii wide nocase

    condition:
      ($a) and any of ($s*)
}
