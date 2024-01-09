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

from logging import ERROR, INFO
import secrets

from flwr.common.logger import log
import grpc


class BearerTokenInterceptor(grpc.ServerInterceptor):
    def __init__(self, token=None):
        self.token = token or secrets.token_hex(32)
        log(
            INFO,
            "Configured Bearer token authentication with: '%s'",
            self.token
        )

        def abort(ignored_request, context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid token")

        self._abortion = grpc.unary_unary_rpc_method_handler(abort)

    def intercept_service(self, continuation, handler_call_details):
        if handler_call_details.method.endswith("Unauthenticated"):
            return continuation(handler_call_details)

        auth_token = None
        for kv in handler_call_details.invocation_metadata:
            if kv.key == "authorization":
                auth_token = kv.value
                break

        if auth_token != "Bearer {}".format(self.token):
            log(
                ERROR,
                "Call with invalid token: %s",
                auth_token
            )
            return self._abortion
        else:
            return continuation(handler_call_details)
