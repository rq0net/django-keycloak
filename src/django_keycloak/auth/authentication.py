import logging
from rest_framework.authentication import BaseAuthentication,\
    TokenAuthentication, get_authorization_header
from django_keycloak.auth.backends import KeycloakIDTokenAuthorizationBackend as BaseKeycloakIDTokenAuthorizationBackend



from rest_framework import HTTP_HEADER_ENCODING, exceptions
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)

class KeycloakIDAuthentication(BaseAuthentication):
    """
    Simple token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ".  For example:

        Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a
    """

    keyword = 'Bearer'
    model = None

    def get_model(self):
        if self.model is not None:
            return self.model
        from django_keycloak.services import oidc_profile
        return oidc_profile

    """
    A custom token model may be used, but must have the following properties.

    * key -- The string identifying the token
    * user -- The user to which the token belongs
    """

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
            client = request.realm.client
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(token, client)

    def authenticate_credentials(self, token, client):
        model = self.get_model()
        try:
            oidc_profile = model.get_or_create_from_id_token(
                    client=client,
                    id_token=token
                )
        except ExpiredSignatureError:
            # If the signature has expired.
            logger.debug('KeycloakBearerAuthorizationBackend: failed to '
                         'authenticate due to an expired access token.')
            raise exceptions.AuthenticationFailed(_('Invalid token.'))
        except JWTClaimsError as e:
            logger.debug('KeycloakBearerAuthorizationBackend: failed to '
                         'authenticate due to failing claim checks: "%s"'
                         % str(e))
            raise exceptions.AuthenticationFailed(_('Invalid claim.'))
        except JWTError:
            # The signature is invalid in any way.
            logger.debug('KeycloakBearerAuthorizationBackend: failed to '
                         'authenticate due to a malformed access token.')
            raise exceptions.AuthenticationFailed(_('Invalid access token2.'))
        else:
            if not oidc_profile.user.is_active:
                raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))
    
            return (oidc_profile.user, token)
        

    def authenticate_header(self, request):
        return self.keyword


    
            
            