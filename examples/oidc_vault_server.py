import os
import pathlib
import sys
import ai4flwr.auth.vault as vault
import flwr as fl

if len(sys.argv) != 3:
    print("Error, No Deployment ID provided!!!")
    print(f"Usage: {sys.argv[0]} <deployment_id> <vault_server>")
    sys.exit(1)

oidc_access_token = os.getenv("OIDC_ACCESS_TOKEN")

if oidc_access_token is None:
    print("Error, No OIDC_ACCESS_TOKEN variable provided!!!")
    sys.exit(1)

deployment_id = sys.argv[1]
vault_server = sys.argv[2]

user_id = vault.get_user_id(oidc_access_token)
secret_path = f"users/{user_id}/deployments/{deployment_id}/federated/"

interceptor = vault.OIDCVaultBearerTokenInterceptor(
    vault_addr=vault_server,
    oidc_access_token=os.getenv("OIDC_ACCESS_TOKEN"),
    secret_path=secret_path,
)


def wavg_metric(metrics):
    global FEDERATED_METRIC
    list_metrics = []
    try:
        list_metrics = ast.literal_eval(FEDERATED_METRIC)
    except ValueError:
        print("Only one metric has been entered.")
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
