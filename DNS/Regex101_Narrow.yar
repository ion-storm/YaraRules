rule Regex101_Narrow
{
    meta:
      author = "b33f"
      type = "Microsoft-Windows-DNS-Client"
      description = "Narrow match; DNS query completed"

    strings:
      $s = /DNS\squery\sis\scompleted.+regex101\.com/ ascii wide nocase

    condition:
      $s
}
