rule query_responses
{
    meta:
      author = "ionstorm"
      type = "Microsoft-Windows-DNS-Client"
      description = "better dns parser"

    strings:
      $a = "Query response for name" ascii wide nocase

    condition:
      $a
}
