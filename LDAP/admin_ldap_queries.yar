rule admin_ldap_queries
{
  meta:
    author = "ionstorm"
    type = "Microsoft-Windows-LDAP-Client"
    description = "MitreRef=T1087,Technique=Account Discovery,Tactic=Discovery,Alert=Admin account discovery via LDAP"

    strings:
      $s = /cn=.*Admin.*/ ascii wide nocase

    condition:
      $s
}