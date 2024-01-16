import os
import pathlib
import sys

import ai4flwr.auth.vault as vault

import flwr as fl

if len(sys.argv) != 2:
    print("Error, No Deployment ID provided!!!")
    print(f"Usage: {sys.argv[0]} <deployment_id>")
    sys.exit(1)

if os.getenv("OIDC_ACCESS_TOKEN") is None:
    print("Error, No OIDC_ACCESS_TOKEN variable provided!!!")
    sys.exit(1)

interceptor = vault.VaultBearerTokenInterceptor(
    vault_addr="https://vault.services.fedcloud.eu:8200",
    oidc_access_token=os.getenv("OIDC_ACCESS_TOKEN"),
    deployment_id=sys.argv[1],
)


def wavg_accuracy(metrics):
    n = sum([i for i, _ in metrics])
    wavg_metric = sum([i * metric["accuracy"] / n for i, metric in metrics])
    return {"accuracy": wavg_metric}


strategy = fl.server.strategy.FedAvg(
    min_available_clients=2,
    evaluate_metrics_aggregation_fn=wavg_accuracy,
)

server = fl.server.start_server(
    server_address="0.0.0.0:5000",
    certificates=(
        pathlib.Path("examples", ".cache", "certificates", "ca.crt").read_bytes(),
        pathlib.Path("examples", ".cache", "certificates", "server.pem").read_bytes(),
        pathlib.Path("examples", ".cache", "certificates", "server.key").read_bytes(),
    ),
    interceptors=[interceptor],
    config=fl.server.ServerConfig(num_rounds=2),
    strategy=strategy,
)
