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

"""Bearer token authentication for Flower server."""

from logging import ERROR, INFO
import signal
import typing

from flwr.common.logger import log
import grpc


class BearerTokenInterceptor(grpc.ServerInterceptor):
    """GRPC Server interceptor implementing Bearer token authentication."""

    def __init__(
        self, *tokens: typing.Optional[str], file: typing.Optional[str] = None
    ) -> None:
        """Create a BearerTokenInterceptor object.

        :param *tokens: One or more strings containing the Bearer tokens that will grant
                        access to the client.

        :param file: A string containing the path to a file containing the Bearer
                     tokens. Please note that the file must contain one token per line
                     and that you cannot use both tokens and file at the same time.
        """
        if not tokens and not file:
            raise ValueError("Must provide either tokens or file")

        if tokens and file:
            raise ValueError("Cannot provide both tokens and file")

        if tokens:
            self.tokens = [t for t in tokens]
            self._file = None

        if file:
            self._file = file
            self.tokens = self._read_tokens_from_file()
            self._signal_handler = signal.signal(signal.SIGUSR1, self._handle_signal)

        log(INFO, "Configured Bearer token authentication with: '%s'", self.tokens)

        def abort(ignored_request, context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid token")

        self._abortion = grpc.stream_stream_rpc_method_handler(abort)

    def _handle_signal(self, signum, frame):
        """Handle signals and reload tokens."""
        if not self._file:
            return
        log(INFO, "Received SIGUSR1, reloading tokens from file")
        self.tokens = self._read_tokens_from_file()
        log(INFO, "Reloaded Bearer token authentication with: '%s'", self.tokens)

    def _read_tokens_from_file(self) -> typing.List[str]:
        """Read the tokens from the file."""
        tokens = []
        with open(self._file, "r") as f:
            for line in f:
                if line:
                    tokens.append(line.strip())
        return tokens

    def intercept_service(self, continuation, handler_call_details):
        """Intercept incoming RPCs checking that the provided token is correct.

        :param continuation: A  function that takes a HandlerCallDetails and proceeds to
                             invoke the next interceptor in the chain, if any, or the
                             RPC handler lookup logic, with the call details passed as
                             an argument, and returns an RpcMethodHandler instance if
                             the RPC is considered serviced, or None otherwise.
        :param handler_call_details: A HandlerCallDetails describing the RPC.

        :returns: Either the continuation (if token is correct) or an abortion.
        """
        if handler_call_details.method.endswith("Unauthenticated"):
            return continuation(handler_call_details)

        auth_token = None
        for kv in handler_call_details.invocation_metadata:
            if kv.key == "x-authorization":
                auth_token = kv.value
                break

        if auth_token.startswith("Bearer "):
            auth_token = auth_token[7:]

            if auth_token in self.tokens:
                return continuation(handler_call_details)

        log(ERROR, "Call with invalid token: '%s'", auth_token)
        return self._abortion


class BearerTokenAuthPlugin(grpc.AuthMetadataPlugin):
    """A Bearer token auth plugin for Flower clients.

    This class should be used againsg a Flower server that is configured with the
    BearerTokenInterceptor as authentication method.
    """

    def __init__(self, token: str) -> None:
        """Initialize the plugin with the provided token.

        :params token: a string containing the token to be used.
        """
        self.token: str = token
        log(INFO, "Created AuthMetadataPlugin with token: %s", self.token)

        super(self.__class__, self).__init__()

    def __call__(self, context, callback):
        """Implement authentication by passing metadata to a callback.

        :context: An AuthMetadataContext providing information on the RPC that the
                  plugin is being called to authenticate.
        :callback: An AuthMetadataPluginCallback to be invoked either synchronously or
                   asynchronously.
        """
        callback((("x-authorization", "Bearer " + self.token),), None)

    def call_credentials(self):
        """Return a CallCredentials object for this plugin.

        :call_credentials: A CallCredentials object.
        """
        return grpc.metadata_call_credentials(self)
