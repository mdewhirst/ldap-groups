from django.contrib import admin
from ldap_groups.models import LDAPGroup
from ldap_groups.views import ldap_search
from django.conf.urls.defaults import *

class LDAPGroupAdmin(admin.ModelAdmin):
    # old-style (sub-)class for some reason ... probably in the docs
    # and is a similar approach to the models class Meta class
    #class Media:
    #    js = ("js/jquery-1.4.2.min.js",
    #          "js/jquery.livequery.js",
    #        )
    def get_urls(self):
        # this is totally baffling atm.
        urls = super(LDAPGroupAdmin, self).get_urls()
        my_urls = patterns('',
            (r'^ldap_search/$', self.admin_site.admin_view(ldap_search)),
        )
        # maybe it is a way to drag in the jquery stuff? Seems tricky.
        return my_urls + urls

admin.site.register(LDAPGroup, LDAPGroupAdmin)
