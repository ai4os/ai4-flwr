<div align="center">
  <img src="https://ai4eosc.eu/wp-content/uploads/sites/10/2022/09/horizontal-transparent.png" alt="logo" width="500"/>
</div>


# ai4-flwr

[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-%23FE5196?logo=conventionalcommits&logoColor=white)](https://conventionalcommits.org)
[![GitHub license](https://img.shields.io/github/license/ai4os/ai4-flwr.svg)](https://github.com/ai4os/ai4-flwr/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/ai4os/ai4-flwr.svg)](https://github.com/ai4os/ai4-flwr/releases)
[![PyPI](https://img.shields.io/pypi/v/ai4flwr.svg)](https://pypi.python.org/pypi/ai4flwr)
[![Python versions](https://img.shields.io/pypi/pyversions/ai4flwr.svg)](https://pypi.python.org/pypi/ai4flwr)


This repository contains the [AI4OS](https://github.com/ai4os) extensions for
the [Flower](https://github.com/adap/flower) framework.

## Authentication

Authentication for Flower is implemented directly via GRPC: interceptors
(server side) and authentication medatata plugins (client side).

In order to use it, the server must be initialized with any object of the
`ai4flwr.auth` package as interceptor. See the examples below for more
details.

### Bearer token authentication

In your server, start it as follows:

    import ai4flwr.auth.bearer

    fl.server.start_server(
        server_address="0.0.0.0:5000",
        certificates=(...),
        interceptors=[ai4flwr.auth.bearer.BearerTokenInterceptor()]
    )

In your client, start it as follows:

    import ai4flwr.auth.bearer

    token = "Your token as configured in the server"

    fl.client.start_numpy_client(
        server_address=f"localhost:5000",
        client=...,
        root_certificates=...
        call_credentials=grpc.metadata_call_credentials(
            ai4flwr.auth.bearer.BearerTokenAuthPlugin(token)
        ),
    )
