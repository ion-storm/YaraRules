rule wmi_commandline
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-WMI-Activity"
    description = "Low effort, high fidelity"

    strings:
      $s = "Commandline=" ascii wide nocase

    condition:
      $s
}
