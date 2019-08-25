rule powershell_encoding
{
    meta:
      author = "ionstorm"
      type = "Microsoft-Windows-PowerShell"
      description = "Powershell Obfuscation Detections"

    strings:
      $s0 = "FromBase64" ascii wide nocase
      $s1 = "AAAAYInlM" ascii wide nocase
      $s2 = "OiCAAAAYInlM" ascii wide nocase
      $s3 = "aHR0cDovL" ascii wide nocase
      $s4 = "h0dHA6Ly" ascii wide nocase
      $s5 = "odHRwOi8v" ascii wide nocase
      $s6 = "aHR0cHM6Ly" ascii wide nocase
      $s7 = "h0dHBzOi8v" ascii wide nocase
      $s8 = "odHRwczovL" ascii wide nocase

    condition:
      any of ($s*)
}
