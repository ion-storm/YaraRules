rule covenant_csharp
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Low effort, high fidelity"

    strings:
      $s = "NativePdbSignature=Microsoft.CSharp.pdb;" ascii wide nocase
      $s1 = "powershell" ascii wide nocase

    condition:
      all of ($s*)
}
