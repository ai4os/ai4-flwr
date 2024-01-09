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

"""Tests for GRPC Authentication classes for Flower clients."""

import pytest

import ai4flwr.auth.client as client


@pytest.fixture
def mock_context():
    pass


@pytest.fixture
def mock_callback():
    def _callback(metadata, error):
        meta = metadata[0]
        assert meta[0] == "authorization"
        assert meta[1] == "Bearer foobar"

    return _callback


def test_client_with_token(mock_context, mock_callback):
    plugin = client.BearerTokenAuthPlugin("foobar")
    assert isinstance(plugin.token, str)
    assert plugin.token == "foobar"

    assert plugin(mock_context, mock_callback) is None
