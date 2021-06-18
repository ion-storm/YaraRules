rule high_risk
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Low effort, high fidelity"

    strings:
      $s0 = "VirtualAlloc" ascii wide nocase
      $s1 = "VirtualAllocEx" ascii wide nocase
      $s2 = "CreateThread" ascii wide nocase
      $s3 = "CreateRemoteThread" ascii wide nocase
      $s4 = "WriteProcessMemory" ascii wide nocase
      $s5 = "FromBase64String" ascii wide nocase
      $s6 = "DownloadFile" ascii wide nocase
      $s7 = "RunPS" ascii wide nocase
      $s8 = "SetThreadContext" ascii wide nocase
      $s9 = "MiniDumpWriteDump" ascii wide nocase
      $s10 = "LoadLibrary" ascii wide nocase
      $s11 = "GetProcAddress" ascii wide nocase
      $s12 = "WaitForSingleObject" ascii wide nocase
      $s13 = "System.IO.MemoryStream" ascii wide nocase

    condition:
      any of ($s*)
}
