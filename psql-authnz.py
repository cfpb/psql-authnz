#!/usr/bin/env python

from pprint import pprint
import os
import ldap

if __name__ == '__main__':
    conn = ldap.initialize('ldap://10.0.1.127:389')

    username = os.getenv("LDAP_USERNAME", None)
    password  = os.getenv("LDAP_PASSWORD", None)

    if username and password:
        auth_tokens = ldap.sasl.digest_md5(username, password)
        conn.sasl_interactive_bind_s("", auth_tokens)
    else:
        conn.simple_bind_s()

    domain = "dc=test,dc=dev"
    group_ou = "ou=Groups"
    group_search_base = group_ou + "," + domain

    data_access_groups = conn.search_s(group_search_base, ldap.SCOPE_SUBTREE, "(objectCLass=groupOfNames)")
    print "Data access groups:"
    pprint(data_access_groups)

    for group in data_access_groups:
        print "Group: " + group[1]['cn'][0] + " has members: "
        print group[1]['member']

    user_ou = "ou=Users"
    user_search_base = user_ou + "," + domain

    results = conn.search_s(user_search_base, ldap.SCOPE_SUBTREE, "(objectClass=*)")
    print "Users:"
    pprint(results)
