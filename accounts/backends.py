from __future__ import print_function
import ldap, sys
import ldap.filter

from django.conf import settings
from django.contrib.auth.models import User, Group

from ldap_groups.models import LDAPGroup

class BaseGroupMembershipBackend(object):
    """
    Base class for implementing an authentication backend which authenticates
    against LDAP and sets Django group membership based on LDAP Organizational
    Unit (OU) membership.
    """


    #######################################################
    # Make BaseGroupMembershipBackend Django 1.3 compliant
    #
    # both these variables will be deprecated in Django 1.4
    supports_anonymous_user = True
    supports_object_permissions = False
    # from 1.4 this backend must support anonymous_user and obj being passed
    # to all methods dealing with permissions and the above vars will not need
    # to be there. Also from 1.4 boolean supports_inactive_user must exist and
    # from 1.5 all methods must handle inactive_user
    supports_inactive_user = True

    def get_all_permissions(self, user, obj=None, inactive_user=False):
        """
        Deliver a set of permissions for the anonymous user
        <app_label>.<codename> eg., 'coltrane.change_category'
        Has absolutely no effect on permissions for logged in users.
        """
        perms = set()
        try:
            # maybe hard code it here or put something in an iterable
            # in the form of [a.add_b, a.change_b, a.delete_b, x.add_y]
            perms = set(settings.ANONYMOUS_PERMISSIONS)
        except AttributeError:
            pass
        # inactive user should get anonymous permissions at least
        if not inactive_user:
            if obj:
                perms.update(self.get_user_object_permissions(user, obj))
        return perms

    def get_user_object_permissions(self, user, obj, inactive_user=False):
        """
        This is internal to this backend. Requires some logic to
        identify specific objects rather than all objects of a
        particular model.
        """
        if not inactive_user:
            pass
        return set()

    # These are the other methods needed for full implementation
    #def get_group_permissions(self, user, obj=None):   return set()
    #def has_perm(self, user, perm, obj=None):          return False
    #def has_perms(self, user, perm_list, obj=None):    return False
    #def has_module_perms(self, user, app_label):       return False
    ###########################################################

    def authenticate(self, username=None, password=None):
        """
        Attempts to bind the provided username and password to LDAP.

        A successful LDAP bind authenticates the user.
        """
        raise NotImplementedError

    def bind_ldap(self, username, password):
        """
        Implements the specific logic necessary to bind a given username and
        password to the particular LDAP server.

        Override this method for each new variety of LDAP backend.
        """
        raise NotImplementedError

    def get_or_create_user(self, username, password):
        """
        Attempts to get the user from the Django db; failing this, creates a
        django.contrib.auth.models.User from details pulled from the specific
        LDAP backend.

        Override this method for each new variety of LDAP backend.
        """
        raise NotImplementedError

    def get_user(self, user_id):
        """
        Implements the logic to retrieve a specific user from the Django db.
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def set_memberships_from_ldap(self, user, membership):
        """
        Assigns user to specific django.contrib.auth.models.Group groups based
        on ldap_group mappings created by the site admin, also assigns staff
        or superuser privileges based on those same mappings.
        """
        ldap_groups = LDAPGroup.objects.filter(org_unit__in=membership)
        for l_grp in ldap_groups:
            for grp in l_grp.groups.all():
                user.groups.add(grp)

        try:
            other_ldap_groups = LDAPGroup.objects.exclude(org_unit__in=membership)
            for l_grp in other_ldap_groups:
                for grp in l_grp.groups.all():
                    user.groups.remove(grp)
        except Exception as e:
            print('%s' % e, file=sys.stderr)

        staff_groups = ldap_groups.filter(make_staff=True).count()
        if staff_groups > 0:
            user.is_staff = True

        superuser_groups = ldap_groups.filter(make_superuser=True).count()
        if superuser_groups > 0:
            user.is_superuser = True
        user.save()


class ActiveDirectoryGroupMembershipSSLBackend(BaseGroupMembershipBackend):

    def bind_ldap(self, username, password):
        try:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,settings.CERT_FILE)
        except AttributeError:
            pass
        ldap.set_option(ldap.OPT_REFERRALS,0) # DO NOT TURN THIS OFF OR SEARCH WON'T WORK!
        l = ldap.initialize(settings.LDAP_URL)
        l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        binddn = "%s@%s" % (username,settings.NT4_DOMAIN)
        l.simple_bind_s(binddn,password)
        return l

    def authenticate(self,username=None,password=None):
        try:
            if len(password) == 0:
                return None
            l = self.bind_ldap(username, password)
            l.unbind_s()
            return self.get_or_create_user(username,password)

        except ImportError:
            pass
        except ldap.INVALID_CREDENTIALS:
            pass

    def get_or_create_user(self, username, password):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:

            try:
                l = self.bind_ldap(username, password)
                # search
                result = l.search_ext_s(settings.SEARCH_DN,ldap.SCOPE_SUBTREE,"sAMAccountName=%s" % username,settings.SEARCH_FIELDS)[0][1]

                if result.has_key('memberOf'):
                    membership = result['memberOf']
                else:
                    membership = None

                # get email
                if result.has_key('mail'):
                    mail = result['mail'][0]
                else:
                    mail = None
                # get surname
                if result.has_key('sn'):
                    last_name = result['sn'][0]
                else:
                    last_name = None

                # get display name
                if result.has_key('givenName'):
                    first_name = result['givenName'][0]
                else:
                    first_name = None

                l.unbind_s()

                user = User(username=username,first_name=first_name,last_name=last_name,email=mail)

            except Exception, e:
                return None

            user.is_staff = False
            user.is_superuser = False
            user.set_unusable_password()
            user.save()

            self.set_memberships_from_ldap(user, membership)

        return user

class eDirectoryGroupMembershipSSLBackend(BaseGroupMembershipBackend):

    """
    TODO 1 - Done in settings.py

    New settings.ALIGN_DJANGO_LDAP_PWORDS to switch on TODO 2, 3 and 4

    TODO 1.1 - Done in settings.py

    New settings.ALIGN_DJANGO_LDAP_GROUPS to switch on TODO 4 on every
    login (True) or only when the password changes (False). True means
    ldap groups can change and update django groups without requiring
    a password change and trigger password-rage among users.

    TODO 2 - Done in get_or_create_user

    If the user's password changes in the ldap backend, it should
    update the django password for that user next time there is a
    successful ldap login

    TODO 3 - Done in authenticate

    If the ldap server is not available, the user should still be able
    to login via the django auth backend. This caters for ACLs
    preventing LDAP login but not fencing off the django website/app.

    A side-effect of this is that the previous password continues to
    work in Django even after the ldap password has been changed. As
    soon as the new password has been used however, it updates the
    django one.

    When the ldap server cannot be contacted we get "Can't contact LDAP
    server" error. It now falls through to the next backend instead of
    that error. It still has the timeout though.

    TODO 4 - Done in BaseGroupMembershipBackend.set_memberships_from_ldap

    Each time there is a password change in ldap or on each login if
    settings.ALIGN_DJANGO_LDAP_GROUPS is True, check the ldap groups for
    that user so the django groups remain in step with ldap groups.

    TODO 5 - Not done

    Find a way to switch is_staff and is_superuser both on and off
    without risking elimination of ALL superusers accidentally when
    playing with ldap groups. Ask me how I know this can happen :)
    """

    def bind_ldap(self, username, password):
        try:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,settings.CERT_FILE)
        except AttributeError:
            pass
        l = ldap.initialize(settings.LDAP_URL)
        l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        l.simple_bind_s(username, password)
        return l

    def authenticate(self,username=None,password=None):
        # called by django auth
        try:
            if len(password) == 0:
                return None
            # get a connection with a known valid bind user
            l = self.bind_ldap(settings.BIND_USER, settings.BIND_PASSWORD)
            base = settings.SEARCH_DN
            scope = ldap.SCOPE_SUBTREE
            retrieve_attributes = ['cn']

            filtered_name = ldap.filter.escape_filter_chars(username)
            # cn didn't work in my system but uid does. miked.
            filter = 'uid=%s' % filtered_name
            #print(filter)

            results = l.search_s(base, scope, filter, retrieve_attributes)
            candidate_dns = [result[0] for result in results]

            l.unbind()
            for dn in candidate_dns:
                try:
                    #print(dn)
                    l = ldap.initialize(settings.LDAP_URL)
                    l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                    # this is the authentication of username dn
                    l.simple_bind_s(dn, password)
                except ldap.INVALID_CREDENTIALS:
                    l.unbind()
                    continue
                l.unbind()
                return self.get_or_create_user(dn, password)

        except ImportError: # ???
            pass
        except ldap.INVALID_CREDENTIALS:
            pass

        except Exception as e:
            print('%s' % e, file=sys.stderr)
            # this causes a 30sec timeout waiting for a non-existent LDAP server
            # before falling through to the next backend listed in settings.py
            #
            return None


    def get_user_detail_from_ldap(self, stripped_name):
        """ factored out of get_or_create_user and should only be
        called from there and get_membership_from_ldap
        """
        l = self.bind_ldap(settings.BIND_USER, settings.BIND_PASSWORD)
        # search
        result = l.search_ext_s(settings.SEARCH_DN,
                                ldap.SCOPE_SUBTREE,
                                #"cn=%s" % stripped_name,
                                "uid=%s" % stripped_name,
                                settings.SEARCH_FIELDS)[0][1]
        l.unbind_s()
        return result


    def get_memberships_from_ldap(self, stripped_name):
        """ bit ugly repeating this - needs refactoring
        """
        result = self.get_user_detail_from_ldap(stripped_name)
        if result.has_key('groupMembership'):
            return result['groupMembership']


    def get_or_create_user(self, username, password):
        stripped_name = ''
        if username.lower().startswith('cn='):
            stripped_name = username.split(',')[0][3:].lower()
        try:
            user = User.objects.get(username=stripped_name)

            try:
                if settings.ALIGN_DJANGO_LDAP_PWORDS:
                    # if the password is different save the new one
                    if not user.check_password(password):
                        user.set_password(password)
                        user.save()
                        # and recheck memberships
                        self.set_memberships_from_ldap(user,
                             self.get_memberships_from_ldap(stripped_name))
                    else:
                        # check groups on every login
                        if settings.ALIGN_DJANGO_LDAP_GROUPS:
                            self.set_memberships_from_ldap(user,
                                 self.get_memberships_from_ldap(stripped_name))
            except AttributeError:
                # in case ALIGN_etc isn't set.
                pass
        except User.DoesNotExist:
            membership = None
            try:
                result = self.get_user_detail_from_ldap(stripped_name)

                if result.has_key('groupMembership'):
                    membership = result['groupMembership']

                # get email
                if result.has_key('mail'):
                    mail = result['mail'][0]
                else:
                    mail = 'missing-email@ldap.source.info'

                # get surname
                if result.has_key('sn'):
                    last_name = result['sn'][0]
                else:
                    last_name = 'Missing-sn'

                # get display name
                if result.has_key('givenName'):
                    first_name = result['givenName'][0]
                else:
                    first_name = stripped_name.title()

                user = User(username=stripped_name,
                            first_name=first_name,
                            last_name=last_name,
                            email=mail)

            except Exception as e:
                print('Search problem with %s\n%s' % (stripped_name,e), file=sys.stderr)
                return None

            user.is_staff = False
            user.is_superuser = False
            try:
                if settings.ALIGN_DJANGO_LDAP_PWORDS:
                    user.set_password(password)
                else:
                    raise AttributeError
            except AttributeError:
                user.set_password('ldap authenticated')
            user.save()
            self.set_memberships_from_ldap(user, membership)
        return user

