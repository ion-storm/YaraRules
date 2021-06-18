rule detect_ironpython
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "MitreRef=T1211,Technique=Exploitation for Defense Evasion,Tactic=Defense Evasion,Alert=ironpython detected"

    strings:
      $s =  "ironpython" ascii wide nocase

    condition:
      $s
}