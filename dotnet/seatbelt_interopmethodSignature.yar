rule SeatBelt_InteropMethodSignature
{
  meta:
    author = "b33f"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Small effort, better resilience"

    strings:
      $s = /bool\(native\sint,valuetype\sw+\.\w+\/TOKEN_INFORMATION_CLASS,native\sint,int32,int32&\);/ ascii wide nocase

    condition:
      $s
}
