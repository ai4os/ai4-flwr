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

"""Tests for GRPC Authentication classes for Flower server."""

import collections

import pytest

from ai4flwr.auth import server


class MockHandlerCallDetais:
    def __init__(self, method, invocation_metadata):
        self.method = method
        self.invocation_metadata = invocation_metadata


@pytest.fixture
def mock_handler_call_details_unauthenticated():
    return MockHandlerCallDetais("Unauthenticated", None)


@pytest.fixture
def mock_handler_call_details_authenticated():
    InvocationMetadata = collections.namedtuple("InvocationMetadata", ["key", "value"])

    return MockHandlerCallDetais(
        "Authenticated",
        [
            InvocationMetadata("authorization", "Bearer foobar"),
        ]
    )


@pytest.fixture
def continuation():
    def _continuation(handler_call_details):
        return "Ok"
    return _continuation


def test_empty_token():
    interceptor = server.BearerTokenInterceptor()
    assert isinstance(interceptor.token, str)
    assert len(interceptor.token) == 64


def test_provided_token():
    interceptor = server.BearerTokenInterceptor("foobar")
    assert isinstance(interceptor.token, str)
    assert len(interceptor.token) == 6
    assert interceptor.token == "foobar"


def test_unauthenticated(mock_handler_call_details_unauthenticated, continuation):
    interceptor = server.BearerTokenInterceptor()
    assert isinstance(interceptor.token, str)
    assert len(interceptor.token) == 64

    ret = interceptor.intercept_service(continuation,
                                        mock_handler_call_details_unauthenticated)
    assert ret == "Ok"


def test_authenticated_not_ok(mock_handler_call_details_authenticated, continuation):
    interceptor = server.BearerTokenInterceptor()
    assert isinstance(interceptor.token, str)
    assert len(interceptor.token) == 64

    ret = interceptor.intercept_service(continuation,
                                        mock_handler_call_details_authenticated)
    assert ret is interceptor._abortion


def test_authenticated_ok(mock_handler_call_details_authenticated, continuation):
    interceptor = server.BearerTokenInterceptor("foobar")
    assert isinstance(interceptor.token, str)

    ret = interceptor.intercept_service(continuation,
                                        mock_handler_call_details_authenticated)
    assert ret == "Ok"
