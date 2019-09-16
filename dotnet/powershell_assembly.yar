rule powershell_assembly
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Small effort, better resilience"

    strings:
    $s1 = "Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" ascii wide nocase
    $s2 = "powershell" ascii wide nocase


    condition:
      all of ($s*)
}
