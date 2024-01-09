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

"""GRPC Authentication classes for Flower clients."""

from logging import INFO

from flwr.common.logger import log
import grpc


class BearerTokenAuthPlugin(grpc.AuthMetadataPlugin):
    """A Bearer token auth plugin for Flower.

    This class should be used againsg a Flower server that is configured with the
    BearerTokenInterceptor as authentication method.
    """

    def __init__(self, token) -> None:
        """Initialize the plugin with the provided token.

        :params token: a string containing the token to be used.
        """
        self.token = token
        log(INFO, "Created AuthMetadataPlugin with token: %s", self.token)

    def __call__(self, context, callback):
        """Implement authentication by passing metadata to a callback.

        :context: An AuthMetadataContext providing information on the RPC that the
                  plugin is being called to authenticate.
        :callback: An AuthMetadataPluginCallback to be invoked either synchronously or
                   asynchronously.
        """
        callback((("authorization", "Bearer " + self.token),), None)
