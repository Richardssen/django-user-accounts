from __future__ import unicode_literals

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q

from account.models import EmailAddress
from account.utils import get_user_lookup_kwargs


class UsernameAuthenticationBackend(ModelBackend):

    def authenticate(self, *args, **credentials):
        User = get_user_model()
        try:
            lookup_kwargs = get_user_lookup_kwargs({
                "{username}__iexact": credentials["username"]
            })
            user = User.objects.get(**lookup_kwargs)
        except (User.DoesNotExist, KeyError):
            return None
        else:
            try:
                if user.check_password(credentials["password"]):
                    return user
            except KeyError:
                return None




def _user_has_perm(user, perm, obj):

    return False



class EmailAuthenticationBackend(ModelBackend):

    def authenticate(self, *args, **credentials):
        qs = EmailAddress.objects.filter(Q(primary=True) | Q(verified=True))
        try:
            email_address = qs.get(email__iexact=credentials["username"])
        except (EmailAddress.DoesNotExist, KeyError):
            return None
        else:
            user = email_address.user
            try:
                if user.check_password(credentials["password"]):
                    return user
            except KeyError:
                return None


    def has_perm(self, user, perm, obj=None):
        """
        Returns True if the user has the specified permission. This method
        queries all available auth backends, but returns immediately if any
        backend returns True. Thus, a user who has permission from a single
        auth backend is assumed to have permission in general. If an object is
        provided, permissions for this specific object are checked.
        """

        # Active superusers have all permissions.
        if user.is_active and user.is_superuser:
            return True

        # Otherwise we need to check the backends.
        return _user_has_perm(user, perm, obj)

