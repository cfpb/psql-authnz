class PSQLAuthnzException(Exception):
    pass

class PSQLAuthnzLDAPException(PSQLAuthnzException):
    pass

class PSQLAuthnzPSQLException(PSQLAuthnzException):
    pass
