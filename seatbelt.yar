rule Seatbelt_GetTokenInformation
{
    strings:
        $s1 = "ManagedInteropMethodName=GetTokenInformation" ascii wide nocase
        $s2 = "TOKEN_INFORMATION_CLASS" ascii wide nocase
        $s3 = /bool\(native int,valuetype \w+\.\w+\/\w+,native int,int32,int32&/ ascii wide nocase
        $s4 = "locals (int32,int64,int64,int64,int64,int32& pinned,bool,int32)" ascii wide nocase

    condition:
        all of ($s*)}
}
