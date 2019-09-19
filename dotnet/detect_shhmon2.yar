rule detect_shhmon_evasion2
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Low effort, high fidelity"

    strings:
      $s =  "ManagedInteropMethodName=FilterFindFirst;" ascii wide nocase
      $s1 = /StubMethodSignature=uint32\(valuetype\s.*\.Win32\/FilterInformationClass,native\sint,uint32,uint32&,native\sint&\);/ ascii wide nocase

    condition:
      all of ($s*)
}