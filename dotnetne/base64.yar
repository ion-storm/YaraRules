
rule base64_anywhere
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Low effort, high fidelity"

    strings:
      $s = "base64" ascii wide nocase

    condition:
      $s
}
