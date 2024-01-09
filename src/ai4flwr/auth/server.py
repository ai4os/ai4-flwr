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

"""GRPC Authentication classes for Flower server."""

from logging import ERROR, INFO
import secrets
import typing

from flwr.common.logger import log
import grpc


class BearerTokenInterceptor(grpc.ServerInterceptor):
    """GRPC Server interceptor implementing Bearer token authentication."""

    def __init__(self, token: typing.Optional[str] = None):
        """Create a BearerTokenInterceptor object.

        :param token: A string containing the Bearer token that will be grant access to
                      the client. If a token is not provided, we will create a random
                      32 bytes hexadecimal string.
        """
        self.token: str = token or secrets.token_hex(32)
        log(INFO, "Configured Bearer token authentication with: '%s'", self.token)

        def abort(ignored_request, context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid token")

        self._abortion = grpc.unary_unary_rpc_method_handler(abort)

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
            if kv.key == "authorization":
                auth_token = kv.value
                break

        if auth_token != "Bearer {}".format(self.token):
            log(ERROR, "Call with invalid token: %s", auth_token)
            return self._abortion
        else:
            return continuation(handler_call_details)
