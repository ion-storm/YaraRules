rule SeatBelt_MethodNamespace
{
  meta:
    author = "b33f"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Low effort, high fidelity"

    strings:
      $s = "MethodNamespace=Seatbelt.Program;" ascii wide nocase

    condition:
      $s
}
