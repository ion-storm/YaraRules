rule detect_sharpsploit
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "MitreRef=T1211,Technique=Exploitation for Defense Evasion,Tactic=Defense Evasion,Alert=sharpsploit detected"

    strings:
      $s =  "sharpsploit" ascii wide nocase

    condition:
      $s
}