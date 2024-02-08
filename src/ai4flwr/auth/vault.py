# -*- coding: utf-8 -*-

# Copyright 2024 Spanish National Research Council (CSIC)
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

import abc
import asyncio
import functools
import logging
import typing

from flwr.common.logger import log
import hvac
import jwt

from ai4flwr.auth import bearer

INFO = logging.INFO
DEBUG = logging.DEBUG
ERROR = logging.ERROR


class BaseVaultBearerTokenInterceptor(bearer.BearerTokenInterceptor, abc.ABC):
    """Vault Bearer token interceptor, abstract class.

    This class will retrieve the list of tokens from Vault, and will
    authenticate the call if the token is on the list.

    This class is abstract, and should be subclassed to implement the
    authentication method. Subclasses should set the _client attribute
    to a valid Vault client before calling the parent __init__ method.
    """

    def __init__(
        self,
        vault_mountpoint: typing.Optional[str] = "/secrets/",
        secret_path: typing.Optional[str] = "federated",  # nosec
    ):
        """Initialize a Vault Bearer Token Interceptor.

        Objects from this class will authenticate calls using the tokens that
        are stored in the given Vault path.

        This is an abstract class, and should be subclassed to implement the
        authentication method. Subclasses should set the _client attribute
        to a valid Vault client before calling the parent __init__ method.

        :param vault_mountpoint: Vault mountpoint
        :param secret_path: Vault path to read tokens from. We will look for secrets
                            stored under that path, if they contain a "token" key, that
                            will be used as bearer tokens.
        """
        if self._client is None:
            raise ValueError("Vault client is not initialized")

        self._client.secrets.kv.default_kv_version = 1

        self._secret_path = secret_path
        self._vault_mountpoint = vault_mountpoint

        vault_addr = self._client.url

        log(INFO, "Configured Vault Bearer token authentication with: '%s'", vault_addr)
        log(INFO, "Reading tokens stored in: '%s'", self._secret_path)
        try:
            log(INFO, "Configured Vault Bearer tokens: '%s'", self.tokens)
        except Exception as e:
            log(ERROR, "Error reading tokens from Vault: '%s'", e)
            raise

        asyncio.run(self.renew())

    # FIXME(aloga): this should be cached, but we need to invalidate the cache
    # when a new token is added or a new token is removed.
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

    async def renew(self, increment: typing.Optional[str] = "12h"):
        """Renew the Vault token.

        This corouting will increase the token validity to the duration given in the
        increment parameter. It will schedule itself to run every half the duration
        of the token obtained.

        :param increment: Renew duration, e.g. ’15s’, ‘20m’, ‘25h’.
        """
        while True:
            log(DEBUG, "Renewing Vault token...")
            self._client.auth.token.renew_self(increment=increment)

            # Print debug info
            response = self._client.auth.token.lookup_self()
            ttl = response.get("data").get("ttl")
            log(DEBUG, "Vault token is valid for %d seconds", ttl)
            log(DEBUG, "Vault token will be renewed in %d secods", ttl / 2)

            # Sleep for half the duration of the token
            await asyncio.sleep(ttl / 2)


class VaultBearerTokenInterceptor(BaseVaultBearerTokenInterceptor):
    """Vault Bearer token interceptor with Vault token authentication.

    This class will retrieve the list of tokens from Vault, and will
    authenticate the call if the token is on the list.
    """

    def __init__(
        self,
        vault_addr: str,
        vault_token: str,
        vault_mountpoint: typing.Optional[str] = "/secrets/",
        secret_path: typing.Optional[str] = "federated",  # nosec
    ):
        """Initialize VaultBearerTokenInterceptor.

        :param vault_addr: Vault address
        :param vault_token: Vault token to authenticate with
        :param vault_mountpoint: Vault mountpoint
        :param secret_path: Vault path to read tokens from. We will look for secrets
                            stored under that path, if they contain a "token" key, that
                            will be used as bearer tokens.
        """
        self._client = hvac.Client(url=vault_addr, token=vault_token)

        super(self.__class__, self).__init__(
            vault_mountpoint=vault_mountpoint,
            secret_path=secret_path,
        )


class OIDCVaultBearerTokenInterceptor(BaseVaultBearerTokenInterceptor):
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
        secret_path: typing.Optional[str] = "federated",  # nosec
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
        self._client = hvac.Client(url=vault_addr)
        self._client.auth.jwt.jwt_login(
            role=vault_role, jwt=oidc_access_token, path=vault_auth_path
        )

        super(self.__class__, self).__init__(
            vault_mountpoint=vault_mountpoint,
            secret_path=secret_path,
        )


def get_user_id(token: str) -> str:
    """Retrieve user ID from OIDC JWT token.

    :param token: OIDC token as a string
    :returns: user ID
    """
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("sub")
    except (jwt.InvalidTokenError, jwt.ExpiredSignatureError) as e:
        log(ERROR, "Invalid OIDC token: '%s'", token)
        raise e
