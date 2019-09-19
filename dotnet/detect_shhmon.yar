rule detect_shhmon_evasion
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Low effort, high fidelity"

    strings:
      $s = /MethodNamespace=System\.Collections\.Generic\.List\`1\[.*\.FilterParser\+FilterInfo\];/ ascii wide nocase
      $s1 = "MethodName=.cctor;" ascii wide nocase

    condition:
      all of ($s*)
}
