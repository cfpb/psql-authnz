import pprint
import logging
import re

import psycopg2
import ldap

from .exceptions import PSQLAuthnzLDAPException, PSQLAuthnzPSQLException


class Synchronizer:
    def __init__(self, global_groups=None, logger=None, pg_ident_file=None,
        username_field="userPrinicpalName", is_citus=0, default_db=None):
        """
        Initializes a syncronizer, with placeholders for the LDAP and PSQL
        connections, plus an optional `global_groups` variable for groups
        that all users should be added to.
        """
        self.ldap_conn = None
        self.psql_conn = None
        self.psql_cur = None
        self.global_groups = global_groups
        self.logger = logger or logging.getLogger(__name__)
        self.pg_ident_file = pg_ident_file
        self.is_citus = is_citus
        self.username_field = username_field
        self.default_db = default_db

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.psql_conn:
            if self.psql_cur:
                self.psql_cur.close()
            self.psql_conn.close()

    def connect_to_ldap(self, ldap_protocol, ldap_host, ldap_port,
                        username, password, method='BASIC'):
        """
        Attempt to connect to Active Directory (LDAP)
        """
        self.logger.debug("Attempting to connect to LDAP...")

        try:
            conn_string = "{}://{}:{}".format(ldap_protocol,
                                              ldap_host,
                                              ldap_port)

            self.logger.debug("Connection string: {0}".format(conn_string))

            self.ldap_conn = ldap.initialize(conn_string)
            self.ldap_conn.set_option(ldap.OPT_REFERRALS, 0)

            # If a username and password is provided, we assume
            # SASL's DIGESTMD5 authentication method.
            self.logger.debug("Auth using method: {0}".format(method))
            if method == "DIGESTMD5":
                if username and password:
                    self.logger.debug(("Username and password provided," +
                                       " attempting DIGEST MD5 connection."))
                    auth_tokens = ldap.sasl.digest_md5(username, password)
                    self.ldap_conn.sasl_interactive_bind_s("", auth_tokens)
                else:
                    raise PSQLAuthnzLDAPException(
                        ("A username and password must supplied " +
                         "for DIGESTMD5 authentication.")
                    )
            else:
                if username and password:
                    self.logger.debug(
                        ("""
                            Username and password provided,
                            attempting simple bind connection.
                        """)
                    )
                    self.ldap_conn.simple_bind_s(username, password)
                else:
                    self.logger.debug(
                        ("No username and password provided, " +
                         "attempting anonymous connection.")
                    )
                    self.ldap_conn.simple_bind_s()

        except Exception as e:
            logging.error(unicode(e.message).encode('utf-8'))
            raise PSQLAuthnzLDAPException()

    def connect_to_psql(self, pg_user, pg_host, pg_password):
        # Connect to Postgres using provided credentials
        conn_string = "dbname=postgres"

        self.logger.debug("Attempting to connect to PSQL...")

        if pg_user:
            conn_string += " user={}".format(pg_user)
        if pg_host:
            conn_string += " host={}".format(pg_host)
        if pg_password:
            conn_string += " password={}".format(pg_password)

        self.logger.debug("Connection string: {0}".format(conn_string))
        try:
            self.psql_conn = psycopg2.connect(conn_string)
            self.psql_conn.autocommit = True
            self.psql_cur = self.psql_conn.cursor()
        except psycopg2.Error as e:
            self.logger.error(unicode(e.message).encode('utf-8'))
            raise PSQLAuthnzPSQLException()
        except Exception as e:
            self.logger.error(unicode(e.message).encode('utf-8'))
            raise e

    def get_groups(self, group_ou, group_class, domain):
        """
        Retrieve all groups within the specified OU.
        """
        self.logger.debug("Retriving LDAP groups...")
        try:
            groups_search_base = group_ou + ',' + domain
            self.logger.debug(
                "Group search base: {0}".format(groups_search_base)
            )
            groups = self.ldap_conn.search_s(
                groups_search_base,
                ldap.SCOPE_SUBTREE,
                "(objectClass={0})".format(group_class)
            )

        except ldap.LDAPError, e:
            self.logger.error(unicode(e.message).encode('utf-8'))
            raise PSQLAuthnzLDAPException(
                "Failed to get groups from the specified OU."
            )
        except Exception as e:
            self.logger.error(unicode(e.message).encode('utf-8'))
            raise e

        self.logger.info(
            "Retrieved {0} group(s) to synchronize...".format(
                len(groups)
            )
        )

        for group in groups:
            self.logger.debug("Found group: {0}".format(group[0]))

        return groups

    def extract_users(self, group_members):
        users = []
        for member in group_members:
            # Get the actual username
            user_match = re.search(
                "uid=(?P<username>[a-zA-Z0-9\_\-\.\/\@]+),.*", member
            )

            if user_match:
                username = user_match.groups('username')[0]
                self.logger.debug(
                    "Extracted username '{}' from '{}'".format(username, member)
                )
            else:
                try:
                    # UID not contained in DN, attempt to retrieve it via LDAP.
                    member_attrs = self.ldap_conn.search_s(
                        member, ldap.SCOPE_BASE, "(objectClass=*)"
                    )
                except ldap.LDAPError, e:
                    self.logger.error(unicode(e.message).encode('utf-8'))
                    raise PSQLAuthnzLDAPException(
                        "Failed to retrieve user attributes from supplied DN."
                    )
                except Exception as e:
                    self.logger.error(unicode(e.message).encode('utf-8'))
                    raise e

                if member_attrs:
                    try:
                        username = member_attrs[0][1][self.username_field][0]
                    except (IndexError, KeyError, ValueError) as e:
                        self.logger.error(
                            "Failed to get username from attrs: {0}".format(
                                member_attrs)
                            )
                        raise e
                else:
                    self.logger.warning(
                        "Couldn't extract username for {}, skipping...".format(
                            member
                        )
                    )
                    continue

            users.append(username)

        return users

    def add_pgident_mapping(self, user):
        if not self.pg_ident_file:
            self.logger.info("No pg_ident file has been defined.")
            return

        try:
            pg_ident = open(self.pg_ident_file, 'r')
            pg_ident_entries = pg_ident.readlines()
            pg_ident.close()

            line_found = False

            for line in pg_ident_entries:
                if user in line:
                    self.logger.debug(
                        "pg_ident entry found for user {}: {}".format(
                            user, line
                        )
                    )
                    line_found = True

            if not line_found:
                self.logger.debug(
                    "No pg_ident entry found, creating entry for {}".format(
                        user
                    )
                )
                pg_ident = open(self.pg_ident_file, 'a')
                pg_ident.write("krb\t{}\t{}\n".format(user, user.lower()))
                pg_ident.close()

        except IOError as e:
            self.logger.error(
                "Error updating pg_ident file: {}".format(
                    unicode(e.message).encode('utf-8')
                )
            )

    def remove_pgident_mapping(self, user):
        """
        Placeholder for function to remove a user from the pgident
        mapping file.
        """
        pass

    def purge_unauthorized_users(self, role_name, authorized_users):
        """
        Removes users in 'role_name' that are not in 'authorized_users'
        """
        lowercase_users = map(
            lambda x: x.lower().replace("'", "").replace('"', ""),
                      authorized_users
        )

        self.logger.debug(
            "Authorized users for role {0}: {1}".format(
                role_name,
                authorized_users
            )
        )

        try:
            self.psql_cur.execute(
                """
                SELECT m.rolname as member
                    FROM pg_authid p
                    INNER JOIN pg_auth_members ON (p.oid=pg_auth_members.roleid)
                    INNER JOIN pg_authid m ON (pg_auth_members.member = m.oid)
                    WHERE p.rolname = '{}'
                """.format(role_name)
            )
        except psycopg2.Error as e:
            self.logger.error(unicode(e.message).encode('utf-8'))
            raise PSQLAuthnzPSQLException()
        except Exception as e:
            self.logger.error(unicode(e.message).encode('utf-8'))
            raise e

        current_members = self.psql_cur.fetchall()
        self.logger.debug(
            "Actual users in role {0}: {1}".format(
                role_name,
                current_members
            )
        )

        for member in current_members:
            member = member[0]
            if member not in lowercase_users:
                self.logger.info(
                    "Removing user '{}' from group '{}'".format(
                        member, role_name
                    )
                )

                try:
                    self.psql_cur.execute(
                        "REVOKE {} FROM {}".format(role_name, member)
                    )
                    if self.is_citus:
                        self.psql_cur.execute(
                        """
                        SELECT RUN_COMMAND_ON_WORKERS($CMD$ REVOKE {} FROM {} $CMD$)
                        """.format(role_name, member)
                    )

                except psycopg2.Error as e:
                    self.logger.error(unicode(e.message).encode('utf-8'))
                    raise PSQLAuthnzPSQLException()
                except Exception as e:
                    self.logger.error(unicode(e.message).encode('utf-8'))
                    raise e

                self.logger.debug(self.psql_cur.statusmessage)

            # TODO: Look up each user in LDAP and make sure they
            # still exist and are active

    def add_authorized_users(self, role_name, authorized_users):
        """
        Ensure 'authorized_users' are in 'role_name'
        """
        for user in authorized_users:
            lowercase_user = user.lower().replace("'", "").replace('"', "")

            # First, check if the user role exists, and create it if it does not
            try:
                self.psql_cur.execute(
                    """
                    SELECT 1 FROM pg_roles
                        WHERE rolname='{0}' AND rolcanlogin='t'
                    """.format(lowercase_user)
                )
                result = self.psql_cur.fetchone()
            except psycopg2.Error as e:
                self.logger.error(unicode(e.message).encode('utf-8'))
                raise PSQLAuthnzPSQLException()
            except Exception as e:
                self.logger.error(unicode(e.message).encode('utf-8'))
                raise e

            if not result or result[0] == 0:
                self.logger.info("Creating new role '{}'".format(lowercase_user))
                try:
                    query = """
                        CREATE ROLE \"{}\" LOGIN INHERIT NOSUPERUSER \
                            NOCREATEDB NOCREATEROLE
                        """.format(lowercase_user)
                    self.logger.debug("Running query {}".format(query))
                    self.psql_cur.execute(query)
                except psycopg2.Error as e:
                    self.logger.error(unicode(e.message).encode('utf-8'))
                    raise PSQLAuthnzPSQLException()

                if self.default_db is not None:
                    self.logger.debug("Allowing {0} to connect to db {1}.".format(lowercase_user, self.default_db))
                    try:
                        query = """
                           GRANT CONNECT ON DATABASE \"{0}\" TO \"{1}\"
                           """.format(self.default_db, lowercase_user)
                        self.logger.debug("Running query {}".format(query)) 
                        self.psql_cur.execute(query)
                    except psycopg2.Error as e:
                        self.logger.error(unicode(e.message).encode('utf-8'))
                        raise PSQLAuthnzPSQLException()

                if self.is_citus:
                    self.logger.debug("Creating user role {} on Citus workers.".format(lowercase_user))
                    query = """
                       SELECT run_command_on_workers($cmd$ CREATE ROLE {} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE $cmd$)
                       """.format(lowercase_user)
                    self.logger.debug("Running query {}".format(query)) 
                    self.psql_cur.execute(query)

                    if self.default_db is not None:
                        self.logger.debug("Allowing {0} to connect to db {1} on Citus Workers.".format(lowercase_user, self.default_db))
                        query = """
                           SELECT run_command_on_workers($cmd$ GRANT CONNECT ON DATABASE {0} TO {1} $cmd$)
                           """.format(self.default_db, lowercase_user)
                        self.logger.debug("Running query {}".format(query)) 
                        self.psql_cur.execute(query)
                
                self.add_pgident_mapping(user)

                if self.global_groups:
                    self.logger.info(
                        "Adding new user {0} to global groups: {1}".format(
                            lowercase_user, ", ".join(self.global_groups)
                        )
                    )

                    for group in self.global_groups:
                        try:
                            self.psql_cur.execute(
                                """
                                GRANT {0} TO {1}
                                """.format(group, lowercase_user)
                            )
                            if self.is_citus:
                                self.psql_cur.execute(
                                """
                                SELECT RUN_COMMAND_ON_WORKERS($CMD$ GRANT {0} TO {1} $CMD$)
                                """.format(group, lowercase_user)
                            )
                        except psycopg2.Error as e:
                            self.logger.error(
                                unicode(e.message).encode('utf-8')
                            )
                            raise PSQLAuthnzPSQLException()
                        except Exception as e:
                            self.logger.error(
                                unicode(e.message).encode('utf-8')
                            )
                            raise e

            # Then, add the user to the role if not already present.
            try:
                self.psql_cur.execute(
                    """
                    SELECT 1 FROM pg_authid g
                        INNER JOIN pg_auth_members ON
                            (g.oid=pg_auth_members.roleid)
                        INNER JOIN pg_authid u ON
                            (pg_auth_members.member=u.oid)
                        WHERE g.rolname = '{0}' AND u.rolname = '{1}'
                    """.format(role_name, lowercase_user)
                )
                result = self.psql_cur.fetchone()
            except psycopg2.Error as e:
                self.logger.error(
                    unicode(e.message).encode('utf-8')
                )
                raise PSQLAuthnzPSQLException()
            except Exception as e:
                self.logger.error(
                    unicode(e.message).encode('utf-8')
                )
                raise e

            # If the role has not already been granted...
            if not result or result[0] == 0:
                self.logger.info("Adding user {0} to role {1}".format(
                    lowercase_user, role_name
                ))
                try:
                    self.psql_cur.execute(
                        "GRANT \"{}\" TO \"{}\"".format(
                            role_name, lowercase_user
                        )
                    )
                    if self.is_citus:
                        self.psql_cur.execute(
                        """
                        SELECT RUN_COMMAND_ON_WORKERS($CMD$ GRANT {} TO {} $CMD$)
                        """.format(role_name, lowercase_user)
                    )
                except psycopg2.Error as e:
                    self.logger.error(unicode(e.message).encode('utf-8'))
                    raise PSQLAuthnzPSQLException()
                except Exception as e:
                    self.logger.error(unicode(e.message).encode('utf-8'))
                    raise e

    def synchronize_group(self, group, prefix, blacklist):
        """
        Synchronize the membership between an LDAP group and a PostgreSQL role
        """

        try:
            group_name = group[1]['cn'][0]
            group_members = group[1]['member']
        except Exception as e:
            self.logger.error("Failed to retrieve group name and members: {0}".format(e))
            return False

        self.logger.debug(
            "Group '{0}' has members: {1}".format(
                group_name, group_members
            )
        )

        role_match = None
        role_match = re.search(
            '^{}(?P<role_name>[a-zA-Z0-9_]+)'.format(prefix), group_name
        )

        if role_match:
            role_name = role_match.groups('role_name')[0]
        else:
            self.logger.warning(
                "Group '{0}' did not match the pattern, skipping...".format(
                    group_name
                )
            )
            return False

        if role_name in blacklist:
            self.logger.info(
                "Skipping group '{0}' which is on the blacklist.".format(
                    group_name
                )
            )
            return False

        # First, ensure that the role exists
        try:
            self.psql_cur.execute(
                "SELECT 1 FROM pg_roles WHERE rolname='{0}'".format(role_name)
            )
            result = self.psql_cur.fetchone()
        except psycopg2.Error as e:
            self.logger.error(unicode(e.message).encode('utf-8'))
            return False

        if not result or result[0] == 0:
            self.logger.warning(
                "Group {0} does not have a PG role, skipping...".format(
                    group_name
                )
            )
            return False

        # Second, extract each member from the list.
        try:
            authorized_users = self.extract_users(group_members)
        except Exception as e:
            self.logger.error(
                "Failed to extract users from LDAP for {0}: {1}".format(
                    group_name, e
                )
            )
            return False

        # Third, add authorized users to the role
        try:
            self.add_authorized_users(role_name, authorized_users)
        except Exception as e:
            self.logger.error(
                "Failed to add users to the PG role for group {0}: {1}".format(
                    group_name, e
                )
            )
            return False

        # Lastly, remove all users that are not on the list
        try:
            self.purge_unauthorized_users(role_name, authorized_users)
        except Exception as e:
            self.logger.error(
                "Failed to remove unauthorized users from group {0}: {1}".format(
                    group_name, e
                )
            )
            return False

        return True

    def synchronize(self, group_ou, group_class, domain, prefix, blacklist):
        self.logger.info(
            "*** Synchronizing Postgres AuthNZ to {0},{1}. ***".format(
                group_ou, domain
            )
        )

        if self.is_citus:
            self.logger.debug("Running in Citus mode.")

        group_count = 0
        for group in self.get_groups(group_ou, group_class, domain):
            try:
                group_name = group[1]['cn'][0]
            except Exception as e:
                self.logger.error(
                    "Failed to get group name from {0}: {1}".format(group, e)
                )

            self.logger.debug("Synchronizing group: {0}".format(group_name))

            if self.synchronize_group(group, prefix, blacklist):
                group_count += 1
            else:
                self.logger.error(
                    "Failed to syncronize group: {0}".format(group_name)
                )

        self.logger.info(
            "*** Successfully synchronized {} group(s) from {},{} ***".format(
                group_count, group_ou, domain
            )
        )
