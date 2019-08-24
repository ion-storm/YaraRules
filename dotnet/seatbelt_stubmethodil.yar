rule Seatbelt_StubMethodIL
{
  meta:
    author = "b33f"
    type = "Microsoft-Windows-DotNETRuntime"
    description = "Small effort, better resilience"

    strings:
    $s1 = /bool\(native\sint,native\sint&\);/ ascii wide nocase
    $s2 = /StubMethodILCode=\/\/\sCode\ssize\\t63\s\(0x003f\)/ ascii wide nocase
    $s3 = /\.locals\s\(int32,int64,int64&\spinned,bool,int32\)/ ascii wide nocase
    $s4 = /native\sint\s\[mscorlib\]\sSystem\.StubHelpers\.StubHelpers::GetStubContext/ ascii wide nocase
    $s5 = /unmanaged\sstdcall\sint32\(int64, native int\)/ ascii wide nocase

    condition:
      all of ($s*)
}
