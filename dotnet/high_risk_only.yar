rule high_risk_only
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "MitreRef=T1211,Technique=Exploitation for Defense Evasion,Tactic=Defense Evasion,Alert=DOTnet High Risk method names"

    strings:
      $s =  "VirtualAlloc" ascii wide nocase
      $s1 = "VirtualAllocEx" ascii wide nocase
      $s2 = "CreateThread" ascii wide nocase
      $s3 = "CreateRemoteThread" ascii wide nocase
      $s4 = "WriteProcessMemory" ascii wide nocase
      $s5 = "FromBase64String" ascii wide nocase
      $s6 = "RunPS" ascii wide nocase
      $s7 = "SetThreadContext" ascii wide nocase
      $s8 = "MiniDumpWriteDump" ascii wide nocase
      $s9 = "LoadLibrary" ascii wide nocase
      $s10 = "GetProcAddress" ascii wide nocase
      $s11 = "WaitForSingleObject" ascii wide nocase
      $s12 = "System.IO.MemoryStream" ascii wide nocase

    condition:
      any of ($s*)
}