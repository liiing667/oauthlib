# -*- coding: utf-8
"""Offline acceptance tests for centralized duplicate-parameter rejection.

Duplicate security-sensitive parameters must be rejected at the endpoint
layer so every grant and extension flow applies the same rule, regardless of
which parser would otherwise win for a duplicated value. All requests here
are fake in-memory objects; no network access is involved.
"""
import json
from unittest import mock

from oauthlib.common import urlencode
from oauthlib.oauth2 import (
    BackendApplicationServer, IntrospectEndpoint, LegacyApplicationServer,
    RequestValidator, RevocationEndpoint, WebApplicationServer,
)
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc8628.endpoints.pre_configured import (
    DeviceApplicationServer,
)

from tests.unittest import TestCase

TOKEN_URI = 'https://example.com/token'
REVOKE_URI = 'https://example.com/revoke'
INTROSPECT_URI = 'https://example.com/introspect'
DEVICE_URI = 'https://example.com/device_authorize'
FORM_HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}
ERROR_HEADERS = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
}


class DuplicateParametersTestBase(TestCase):

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = 'https://a.b/cb'
        self.validator.get_code_challenge.return_value = None
        self.validator.client_authentication_required.return_value = False
        self.validator.authenticate_client_id.side_effect = self.set_client_id

    def set_client_id(self, client_id, request, *args, **kwargs):
        request.client = mock.MagicMock()
        request.client.client_id = client_id
        return True

    def assert_duplicate_error(self, response, param):
        headers, body, status = response
        self.assertEqual(status, 400)
        self.assertEqual(headers, ERROR_HEADERS)
        payload = json.loads(body)
        self.assertEqual(payload['error'], 'invalid_request')
        self.assertEqual(payload['error_description'],
                         'Duplicate %s parameter.' % param)


class TokenEndpointDuplicateParamsTest(DuplicateParametersTestBase):

    def setUp(self):
        super().setUp()
        self.validator.authenticate_client.side_effect = self.set_client
        self.web = WebApplicationServer(self.validator)
        self.legacy = LegacyApplicationServer(self.validator)
        self.backend = BackendApplicationServer(self.validator)

    def set_client(self, request, *args, **kwargs):
        request.client = mock.MagicMock()
        request.client.client_id = request.client_id
        return True

    def test_authorization_code_grant_rejects_duplicates(self):
        for param, body in (
            ('code', 'grant_type=authorization_code&code=abc&code=def'),
            ('code_verifier',
             'grant_type=authorization_code&code=abc&code_verifier=aaa&code_verifier=bbb'),
            ('client_id',
             'grant_type=authorization_code&code=abc&client_id=foo&client_id=bar'),
            ('redirect_uri',
             'grant_type=authorization_code&code=abc&redirect_uri=https%3A%2F%2Fa.b%2F1&redirect_uri=https%3A%2F%2Fa.b%2F2'),
            ('grant_type',
             'grant_type=authorization_code&grant_type=refresh_token&code=abc'),
        ):
            response = self.web.create_token_response(
                TOKEN_URI, body=body, headers=FORM_HEADERS)
            self.assert_duplicate_error(response, param)
            self.validator.save_token.assert_not_called()

    def test_refresh_grant_rejects_duplicates(self):
        for param, body in (
            ('refresh_token',
             'grant_type=refresh_token&refresh_token=abc&refresh_token=def'),
            ('scope',
             'grant_type=refresh_token&refresh_token=abc&scope=a&scope=b'),
            ('client_secret',
             'grant_type=refresh_token&refresh_token=abc&client_secret=s1&client_secret=s2'),
        ):
            response = self.web.create_token_response(
                TOKEN_URI, body=body, headers=FORM_HEADERS)
            self.assert_duplicate_error(response, param)
            self.validator.save_token.assert_not_called()

    def test_password_and_client_credentials_grants_reject_duplicates(self):
        bodies = (
            ('password',
             'grant_type=password&username=foo&password=bar&password=baz'),
            ('username',
             'grant_type=password&username=foo&username=bar&password=baz'),
            ('scope',
             'grant_type=client_credentials&scope=foo&scope=bar'),
        )
        servers = (self.legacy, self.legacy, self.backend)
        for (param, body), server in zip(bodies, servers):
            response = server.create_token_response(
                TOKEN_URI, body=body, headers=FORM_HEADERS)
            self.assert_duplicate_error(response, param)

    def test_unknown_duplicate_param_is_ignored(self):
        # RFC 6749: unrecognized parameters are ignored, even when repeated.
        body = ('grant_type=authorization_code&code=abc'
                '&custom_ext=x&custom_ext=y')
        self.validator.validate_code.return_value = True
        self.validator.confirm_redirect_uri.return_value = True
        response = self.web.create_token_response(
                TOKEN_URI, body=body, headers=FORM_HEADERS)
        _headers, response_body, status = response
        self.assertNotEqual(status, 400)
        self.assertNotIn('Duplicate', response_body)

    def test_single_valued_requests_still_succeed(self):
        self.validator.validate_code.return_value = True
        self.validator.confirm_redirect_uri.return_value = True
        self.validator.validate_refresh_token.return_value = True
        self.validator.get_original_scopes.return_value = ['foo']

        with mock.patch('oauthlib.common.generate_token', return_value='tok'):
            _headers, body, status = self.web.create_token_response(
                TOKEN_URI,
                body='grant_type=authorization_code&code=abc',
                headers=FORM_HEADERS)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)['access_token'], 'tok')

        with mock.patch('oauthlib.common.generate_token', return_value='tok'):
            _headers, body, status = self.web.create_token_response(
                TOKEN_URI,
                body='grant_type=refresh_token&refresh_token=abc',
                headers=FORM_HEADERS)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)['access_token'], 'tok')


class RevocationEndpointDuplicateParamsTest(DuplicateParametersTestBase):

    def setUp(self):
        super().setUp()
        self.validator.client_authentication_required.return_value = True
        self.validator.authenticate_client.side_effect = self.set_client
        self.endpoint = RevocationEndpoint(self.validator)

    def set_client(self, request, *args, **kwargs):
        request.client = mock.MagicMock()
        request.client.client_id = 'foo'
        return True

    def test_revocation_rejects_duplicate_token_and_hint(self):
        for param, pairs in (
            ('token', [('token', 'a'), ('token', 'b')]),
            ('token_type_hint', [('token', 'a'),
                                  ('token_type_hint', 'access_token'),
                                  ('token_type_hint', 'refresh_token')]),
        ):
            response = self.endpoint.create_revocation_response(
                REVOKE_URI, body=urlencode(pairs), headers=FORM_HEADERS)
            self.assert_duplicate_error(response, param)
            self.validator.revoke_token.assert_not_called()

    def test_revocation_accepts_single_valued_request(self):
        body = urlencode([('token', 'abc'),
                          ('token_type_hint', 'access_token')])
        _h, body_out, status = self.endpoint.create_revocation_response(
            REVOKE_URI, body=body, headers=FORM_HEADERS)
        self.assertEqual(status, 200)
        self.assertEqual(body_out, '')
        self.validator.revoke_token.assert_called_once()


class IntrospectEndpointDuplicateParamsTest(DuplicateParametersTestBase):

    def setUp(self):
        super().setUp()
        self.validator.client_authentication_required.return_value = True
        self.validator.authenticate_client.side_effect = self.set_client
        self.endpoint = IntrospectEndpoint(self.validator)

    def set_client(self, request, *args, **kwargs):
        request.client = mock.MagicMock()
        request.client.client_id = 'foo'
        return True

    def test_introspect_rejects_duplicate_token_and_hint(self):
        for param, pairs in (
            ('token', [('token', 'a'), ('token', 'b')]),
            ('token_type_hint', [('token', 'a'),
                                  ('token_type_hint', 'access_token'),
                                  ('token_type_hint', 'refresh_token')]),
        ):
            response = self.endpoint.create_introspect_response(
                INTROSPECT_URI, body=urlencode(pairs), headers=FORM_HEADERS)
            self.assert_duplicate_error(response, param)
            self.validator.introspect_token.assert_not_called()

    def test_introspect_accepts_single_valued_request(self):
        self.validator.introspect_token.return_value = None
        body = urlencode([('token', 'abc')])
        _h, body_out, status = self.endpoint.create_introspect_response(
            INTROSPECT_URI, body=body, headers=FORM_HEADERS)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body_out), {'active': False})


class DeviceFlowDuplicateParamsTest(DuplicateParametersTestBase):

    def setUp(self):
        super().setUp()
        self.validator.authenticate_client.side_effect = self.set_client
        self.device = DeviceApplicationServer(
            self.validator, 'https://example.com/verify')
        self.web = WebApplicationServer(self.validator)

    def set_client(self, request, *args, **kwargs):
        request.client = mock.MagicMock()
        request.client.client_id = request.client_id
        return True

    def test_device_authorization_rejects_duplicates(self):
        for param, body in (
            ('client_id', 'client_id=foo&client_id=bar'),
            ('scope', 'client_id=foo&scope=a&scope=b'),
        ):
            with self.assertRaises(errors.InvalidRequestFatalError) as caught:
                self.device.create_device_authorization_response(
                    DEVICE_URI, body=body, headers=FORM_HEADERS)
            self.assertEqual(caught.exception.description,
                             'Duplicate %s parameter.' % param)

    def test_device_token_request_rejects_duplicates(self):
        body = ('grant_type=urn:ietf:params:oauth:grant-type:device_code'
                '&device_code=abc&device_code=def')
        response = self.web.create_token_response(
            TOKEN_URI, body=body, headers=FORM_HEADERS)
        self.assert_duplicate_error(response, 'device_code')
        self.validator.save_token.assert_not_called()

    def test_device_authorization_accepts_single_valued_request(self):
        self.validator.get_default_scopes.return_value = []
        _h, data, status = self.device.create_device_authorization_response(
            DEVICE_URI, body='client_id=foo', headers=FORM_HEADERS)
        self.assertEqual(status, 200)
        self.assertIn('device_code', data)
        self.assertIn('user_code', data)


class AuthorizationEndpointDuplicateParamsTest(DuplicateParametersTestBase):

    def setUp(self):
        super().setUp()
        self.validator.validate_client_id.return_value = True
        self.web = WebApplicationServer(self.validator)

    def test_authorization_request_rejects_duplicates_with_fatal_error(self):
        base = 'https://example.com/auth?response_type=code&client_id=foo'
        for param, query in (
            ('state', base + '&state=a&state=b'),
            ('response_type',
             'https://example.com/auth?response_type=code&response_type=token&client_id=foo'),
            ('code_challenge',
             base + '&code_challenge=aaa&code_challenge=bbb'),
        ):
            with self.assertRaises(errors.InvalidRequestFatalError) as caught:
                self.web.validate_authorization_request(query)
            self.assertEqual(caught.exception.description,
                             'Duplicate %s parameter.' % param)

    def test_single_valued_authorization_request_succeeds(self):
        self.validator.get_default_redirect_uri.return_value = 'https://a.b/cb'
        uri = ('https://example.com/auth?response_type=code'
               '&client_id=foo&state=abc')
        _scopes, request_info = self.web.validate_authorization_request(uri)
        self.assertEqual(request_info['state'], 'abc')
