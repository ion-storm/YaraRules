rule automation_wo_powershell
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Low effort, high fidelity"

    strings:
      $s = "NativePdbSignature=System.Management.Automation.pdb;" ascii wide nocase
      $t = "powershell" ascii wide nocase

    condition:
      $s and not $t
}
