# excerpt from settings.py
#
# Auth LDAP # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# LDAP
# NT4_DOMAIN is used with Active Directory only, comment out for eDirectory
# NT4_DOMAIN = 'EXAMPLE'
# sAMAccountName is used with Active Directory
# SEARCH_FIELDS retrieves specified info from ldap server after finding user
#    Use the following for Active Directory
# SEARCH_FIELDS = ['mail','givenName','sn','sAMAccountName','memberOf','cn']
#    Use the following for Novell eDirectory
# SEARCH_FIELDS = ['mail', 'givenName', 'sn', 'groupMembership', 'cn']
#
SEARCH_FIELDS = ['mail', 'givenName', 'sn', 'groupMembership', 'cn', 'uid', 'o', 'ou']

ldaphost = getcreds('ldap.host')
BIND_USER = ldaphost[0]             # distinguished name
BIND_PASSWORD = ldaphost[1]         #
ldap_srv = ldaphost[2]              # IP address
ssl_port = ldaphost[3]              # 636
ldap_cert = ldaphost[4]             # base64
SEARCH_DN = ldaphost[5]             # o=organization
#if DEBUG: print('\nBIND_USER = %s' % BIND_USER)

ssl = True                          # switch between SSL and non-SSL

if ssl:
    protocol = 'ldaps'
    ldap_port = ssl_port
    # here is a Novell CA cert to certify my Novell self-signed chappie
    CERT_FILE = '%s/%s' % (credsdir, ldap_cert)
    tag = 'Cert file ='
    if not os.path.isfile(CERT_FILE):
        tag = 'NOT A FILE :'
    #if DEBUG: print('%s %s' % (tag, CERT_FILE))
else:
    protocol = 'ldap'
    ldap_port = 389
    # CERT_FILE = '' # don't use if ssl==False - backend relies on exception

LDAP_URL = '%s://%s:%s' % (protocol, ldap_srv, ldap_port)
# mod_wsgi restricts IO to sys.stdout
# from __future__ import print_function
# print(LDAP_URL, file=sys.stderr)

# True will update passwords and group memberships in django from ldap_groups
# False will keep them as originally created in django no matter what
ALIGN_DJANGO_LDAP_PWORDS = True

# ALIGN_DJANGO_LDAP_GROUPS requires ALIGN_DJANGO_LDAP_PWORDS = True
# True means check groups every login. False means to only check groups
# when the password changes in ldap and is actually used in a django app
ALIGN_DJANGO_LDAP_GROUPS = True

AUTHENTICATION_BACKENDS = (
    #'ldap_groups.accounts.backends.ActiveDirectoryGroupMembershipSSLBackend',
    'ldap_groups.accounts.backends.eDirectoryGroupMembershipSSLBackend',
    'django.contrib.auth.backends.ModelBackend',
    )

# in the form of [a.add_b, a.change_b, a.delete_b, x.add_y]
ANONYMOUS_PERMISSIONS = []

INSTALLED_APPS += (
    'ldap_groups',                  # Novell login for auth
)
