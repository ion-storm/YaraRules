rule powershell_generic
{
    meta:
      author = "ionstorm"
      type = "Microsoft-Windows-PowerShell"
      description = "Generic Powershell Detections"

    strings:
      $s0 = "psexec" ascii wide nocase
      $s1 = "whoami" ascii wide nocase
      $s2 = "net use" ascii wide nocase
      $s3 = "VerbosePreference.ToString" ascii wide nocase
      $s4 = " iex " ascii wide nocase
      $s5 = "invoke-expression" ascii wide nocase
      $s7 = " iwr " ascii wide nocase
      $s8 = "invoke-webrequest" ascii wide nocase
      $s9 = "System.Net.WebRequest" ascii wide nocase
      $s10 = "shellcode" ascii wide nocase
      $s11 = "System.Net.CredentialCache" ascii wide nocase

    condition:
      any of ($s*)
}
