# -*- coding: utf-8 -*-

# Copyright 2019 Spanish National Research Council (CSIC)
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Authentication for Flower server, using Vault secrets as Bearer tokens."""

import functools
from logging import ERROR, INFO
import typing

from flwr.common.logger import log
import hvac
import jwt

from ai4flwr.auth import bearer


class OIDCVaultBearerTokenInterceptor(bearer.BearerTokenInterceptor):
    """Vault Bearer token interceptor with OIDC authentication.

    This class will retrieve the list of tokens from Vault, and will
    authenticate the call if the token is on the list.
    """

    def __init__(
        self,
        vault_addr: str,
        oidc_access_token: str,
        vault_role: typing.Optional[str] = "",
        vault_auth_path: typing.Optional[str] = "jwt",
        vault_mountpoint: typing.Optional[str] = "/secrets/",
        secret_path: typing.Optional[str] = "federated",
    ):
        """Initialize VaultBearerTokenInterceptor.

        :param vault_addr: Vault address
        :param oidc_access_token: OIDC access token to authenticate with Vault
        :param vault_role: Vault role to use for authentication
        :param vault_auth_path: Vault authentication path
        :param vault_mountpoint: Vault mountpoint
        :param secret_path: Vault path to read tokens from. We will look for secrets
                            stored under that path, if they contain a "token" key, that
                            will be used as bearer tokens.
        """

        # FIXME(aloga): the token will expire after some time, we should
        # reauthenticate, or use Vault + Nomad integration to avoid using the oidc
        # token at all
        self._client = hvac.Client(url=vault_addr)
        self._client.auth.jwt.jwt_login(
            role=vault_role,
            jwt=oidc_access_token,
            path=vault_auth_path
        )
        self._client.secrets.kv.default_kv_version = 1

        # FIXME(aloga): can we use v2 and configure the mountpoint?
        self._vault_mountpoint = vault_mountpoint

        self._secret_path = secret_path

        log(INFO, "Configured Vault Bearer token authentication with: '%s'", vault_addr)
        log(INFO, "Reading tokens stored in: '%s'", self._secret_path)
        try:
            log(INFO, "Configured Vault Bearer tokens: '%s'", self.tokens)
        except Exception as e:
            log(ERROR, "Error reading tokens from Vault: '%s'", e)
            raise

    # FIXME(aloga): this should be cached, but we need to invalidate the cache
    # when a new token is added or a new token is removed. Morever, since authentication
    # based on OIDC tokens againt Vault will stop working after some time (i.e. when
    # the OIDC token expires), we can use this function for testing, but we should
    # not use it in production.
    @functools.cached_property
    def tokens(self) -> typing.List[str]:
        """Get list of tokens from Vault.

        :returns: list of tokens
        """
        print("Getting tokens from Vault -> ", self._secret_path)
        response = self._client.secrets.kv.list_secrets(
            mount_point=self._vault_mountpoint,
            path=self._secret_path,
        )
        secrets = response.get("data", {}).get("keys", [])

        tokens = []
        for s in secrets:
            secret = self._client.secrets.kv.read_secret(
                mount_point=self._vault_mountpoint,
                path=f"{self._secret_path}/{s}",
            )
            token = secret.get("data", {}).get("token")
            if token:
                tokens.append(token)
        return tokens

    def renew(
        self,
        increment: typing.Optional[str] = "768h",
    ):
        """ Renew the Vault token, increase its validity to the duration given in the increment parameter.

        :param increment: Renew duration, e.g. ’15s’, ‘20m’, ‘25h’.
        """
        self._client.auth.token.renew_self(increment=increment)

        # Print debug info
        response = self._client.auth.token.lookup_self()
        ttl = response.get("data").get("ttl")
        log(INFO, "Vault token is valid for %d seconds", ttl)


def get_user_id(token: str) -> str:
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("sub")
    except (jwt.InvalidTokenError, jwt.ExpiredSignatureError) as e:
        log(ERROR, "Invalid OIDC token: '%s'", token)
        raise e
