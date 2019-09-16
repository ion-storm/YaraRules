rule powershell_automation
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Low effort, high fidelity"

    strings:
      $s = "NativePdbSignature=System.Management.Automation.pdb;" ascii wide nocase
      $s1 = "powershell" ascii wide nocase

    condition:
      all of ($s*)
}
