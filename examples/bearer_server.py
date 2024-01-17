import pathlib
import sys

import ai4flwr.auth.bearer as bearer

import flwr as fl

if len(sys.argv) != 2:
    print("Error, No token has been provided!!!")
    print(f"Usage: {sys.argv[0]} <token>")
    sys.exit(1)

interceptor = bearer.BearerTokenInterceptor(sys.argv[1])


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
