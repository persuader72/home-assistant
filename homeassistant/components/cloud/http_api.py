"""The HTTP api to control the cloud integration."""
import asyncio
import logging

import voluptuous as vol
import async_timeout

from homeassistant.components.http import (
    HomeAssistantView, RequestDataValidator)

from . import auth_api
from .const import REQUEST_TIMEOUT

_LOGGER = logging.getLogger(__name__)


@asyncio.coroutine
def async_setup(hass):
    """Initialize the HTTP api."""
    hass.http.register_view(CloudLoginView)
    hass.http.register_view(CloudLogoutView)
    hass.http.register_view(CloudAccountView)
    hass.http.register_view(CloudRegisterView)
    hass.http.register_view(CloudConfirmRegisterView)
    hass.http.register_view(CloudForgotPasswordView)
    hass.http.register_view(CloudConfirmForgotPasswordView)


class CloudLoginView(HomeAssistantView):
    """Login to Home Assistant cloud."""

    url = '/api/cloud/login'
    name = 'api:cloud:login'

    @asyncio.coroutine
    @RequestDataValidator(vol.Schema({
        vol.Required('email'): str,
        vol.Required('password'): str,
    }))
    def post(self, request, data):
        """Handle login request."""
        hass = request.app['hass']
        auth = hass.data['cloud']['auth']

        try:
            with async_timeout.timeout(REQUEST_TIMEOUT, loop=hass.loop):
                yield from hass.async_add_job(auth.login, data['email'],
                                              data['password'])

        except auth_api.UserNotFound:
            return self.json_message("User doesn't exist.", 400)
        except auth_api.Unauthenticated:
            return self.json_message('Authentication failed.', 401)
        except auth_api.PasswordChangeRequired:
            return self.json_message('Password change required.', 400)
        except auth_api.UnexpectedError as err:
            return self.json_message('Unexpected error: {}.'.format(err), 500)
        except asyncio.TimeoutError:
            return self.json_message(
                'Unable to reach Home Assistant cloud.', 502)

        return self.json(_auth_data(auth))


class CloudLogoutView(HomeAssistantView):
    """Log out of the Home Assistant cloud."""

    url = '/api/cloud/logout'
    name = 'api:cloud:logout'

    @asyncio.coroutine
    def post(self, request):
        """Handle logout request."""
        hass = request.app['hass']
        auth = hass.data['cloud']['auth']

        try:
            with async_timeout.timeout(REQUEST_TIMEOUT, loop=hass.loop):
                yield from hass.async_add_job(auth.logout)

            return self.json({
                'result': 'ok',
            })
        except asyncio.TimeoutError:
            return self.json_message("Could not reach the server.", 502)
        except auth_api.UnexpectedError as err:
            return self.json_message("Unexpected error: {}.".format(err), 502)


class CloudAccountView(HomeAssistantView):
    """View to retrieve account info."""

    url = '/api/cloud/account'
    name = 'api:cloud:account'

    @asyncio.coroutine
    def get(self, request):
        """Get account info."""
        hass = request.app['hass']
        auth = hass.data['cloud']['auth']

        if not auth.is_logged_in:
            return self.json_message('Not logged in', 400)

        return self.json(_auth_data(auth))


class CloudRegisterView(HomeAssistantView):
    """Register on the Home Assistant cloud."""

    url = '/api/cloud/register'
    name = 'api:cloud:register'

    @asyncio.coroutine
    @RequestDataValidator(vol.Schema({
        vol.Required('email'): str,
        vol.Required('password'): str,
    }))
    def post(self, request, data):
        """Handle registration request."""
        hass = request.app['hass']

        try:
            with async_timeout.timeout(REQUEST_TIMEOUT, loop=hass.loop):
                yield from hass.async_add_job(
                    auth_api.register, hass, data['email'], data['password'])

            return self.json({
                'result': 'ok',
            })
        except asyncio.TimeoutError:
            return self.json_message("Could not reach the server.", 502)
        except auth_api.UnexpectedError as err:
            return self.json_message("Unexpected error: {}.".format(err), 502)


class CloudConfirmRegisterView(HomeAssistantView):
    """Confirm registration on the Home Assistant cloud."""

    url = '/api/cloud/confirm_register'
    name = 'api:cloud:confirm_register'

    @asyncio.coroutine
    @RequestDataValidator(vol.Schema({
        vol.Required('confirmation_code'): str,
        vol.Required('email'): str,
    }))
    def post(self, request, data):
        """Handle registration confirmation request."""
        hass = request.app['hass']

        try:
            with async_timeout.timeout(REQUEST_TIMEOUT, loop=hass.loop):
                yield from hass.async_add_job(
                    auth_api.confirm_register, hass, data['confirmation_code'],
                    data['email'])

            return self.json({
                'result': 'ok',
            })
        except asyncio.TimeoutError:
            return self.json_message("Could not reach the server.", 502)
        except auth_api.UnexpectedError as err:
            return self.json_message("Unexpected error: {}.".format(err), 502)


class CloudForgotPasswordView(HomeAssistantView):
    """View to start Forgot Password flow.."""

    url = '/api/cloud/forgot_password'
    name = 'api:cloud:forgot_password'

    @asyncio.coroutine
    @RequestDataValidator(vol.Schema({
        vol.Required('email'): str,
    }))
    def post(self, request, data):
        """Handle forgot password request."""
        hass = request.app['hass']

        try:
            with async_timeout.timeout(REQUEST_TIMEOUT, loop=hass.loop):
                yield from hass.async_add_job(
                    auth_api.forgot_password, hass, data['email'])

            return self.json({
                'result': 'ok',
            })
        except auth_api.UserNotFound:
            return self.json_message("User doesn't exist.", 400)
        except asyncio.TimeoutError:
            return self.json_message("Could not reach the server.", 502)
        except auth_api.UnexpectedError as err:
            return self.json_message("Unexpected error: {}.".format(err), 502)


class CloudConfirmForgotPasswordView(HomeAssistantView):
    """View to finish Forgot Password flow.."""

    url = '/api/cloud/confirm_forgot_password'
    name = 'api:cloud:confirm_forgot_password'

    @asyncio.coroutine
    @RequestDataValidator(vol.Schema({
        vol.Required('confirmation_code'): str,
        vol.Required('email'): str,
        vol.Required('new_password'): vol.All(str, vol.Length(min=6))
    }))
    def post(self, request, data):
        """Handle forgot password confirm request."""
        hass = request.app['hass']

        try:
            with async_timeout.timeout(REQUEST_TIMEOUT, loop=hass.loop):
                yield from hass.async_add_job(
                    auth_api.confirm_forgot_password, hass,
                    data['confirmation_code'], data['email'],
                    data['new_password'])

            return self.json({
                'result': 'ok',
            })
        except auth_api.ExpiredCode:
            return self.json_message(
                'Invalid code provided, please request a code again.', 400)
        except asyncio.TimeoutError:
            return self.json_message("Could not reach the server.", 502)
        except auth_api.UnexpectedError as err:
            return self.json_message("Unexpected error: {}.".format(err), 502)


def _auth_data(auth):
    """Generate the auth data JSON response."""
    return {
        'email': auth.account.email
    }
