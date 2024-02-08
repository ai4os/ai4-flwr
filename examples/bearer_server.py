import pathlib
import sys

import ai4flwr.auth.bearer as bearer

from logging import ERROR, INFO

import flwr as fl

FEDERATED_METRIC = "accuracy"

if len(sys.argv) != 2:
    print("Error, No token has been provided!!!")
    print(f"Usage: {sys.argv[0]} <token>")
    sys.exit(1)

interceptor = bearer.BearerTokenInterceptor(sys.argv[1])

def wavg_metric(metrics):
    global FEDERATED_METRIC
    list_metrics = []
    try:
        list_metrics = ast.literal_eval(FEDERATED_METRIC)
    except ValueError:
        log(INFO, "Only one metric has been entered.")
    if len(list_metrics) == 0:
        n = sum([i for i, _ in metrics])
        wavg_metric = sum([i * metric[FEDERATED_METRIC] / n for i, metric in metrics])
        return {FEDERATED_METRIC: wavg_metric}
    else:
        n = sum([i for i, _ in metrics])
        dict_metrics = {}
        for fed_metric in list_metrics:
            wavg_metric = sum([i * metric[fed_metric] / n for i, metric in metrics])
            dict_metrics[fed_metric] = wavg_metric
        return dict_metrics


strategy = fl.server.strategy.FedAvg(
    min_available_clients=2,
    min_fit_clients=2,
    evaluate_metrics_aggregation_fn=wavg_metric,
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
