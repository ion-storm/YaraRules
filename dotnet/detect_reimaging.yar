rule detect_reimaging
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Low effort, high fidelity"

    strings:
      $s = /CommandLine=.*exe.*.exe.*.exe/ ascii wide nocase
      $s1 = "StartupFlags=CONCURRENT_GC" ascii wide nocase
	  $s2 = "clr.dll" ascii wide nocase

    condition:
      all of ($s*)
}
