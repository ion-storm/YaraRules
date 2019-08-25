rule dns_testing2
{
    meta:
      author = "ionstorm"
      type = "Microsoft-Windows-DNS-Client"
      description = "better dns parser"

    strings:
      $a = "DNS query is completed for the name" ascii wide nocase

    condition:
      $a
}
