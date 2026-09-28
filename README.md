# Hetero Secret Manager

Hetero Secret Manager is the OpenBao backend for HeteroCloud. Users configure
container secrets in each Flash service's detail page. The API stores values
in OpenBao and mounts selected secrets as read-only files in the container.
OpenBao's native UI is disabled. Its VPN gateway serves only the `/v1` API.
Keycloak OIDC remains available for operator CLI access. The `owner` role is
bound to one existing Keycloak subject; ordinary users can access only their
own `secret/data/users/<their entity ID>/*` subtree through the API.

The deployment is GitOps-managed through the OpenBao Argo CD application in
[HeteroNetwork](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork).
`deploy/chart` pins the official OpenBao chart, the server image, TLS, the
VPN-only route, network policy, and backup CronJob. The three Raft voters each
use node-local ext4 storage for OpenBao's barrier-encrypted Raft data on
`uc-k8sp1`, `uc-k8sp2`, or `uc-k8s3p`. These control-plane hosts admit no other
application workloads. The hostname resolves only to VPN addresses, and its
external HTTP gateways return 403. A ClusterIP-only Envoy Gateway selects the
current Raft leader via OpenBao's Kubernetes
service-registration label so writes and following reads reach the same voter.

Flash service secrets are registered from each service's detail page. The API
writes values to OpenBao KV v2 and
stores only secret names in the Flash service spec. The Agent Injector makes
selected secrets available as read-only files under `/vault/secrets/` inside
the container. Each service has its own Kubernetes service account and can
read only its own KV subtree.
To reconcile the two Kubernetes auth roles after a deployment, use an owner
token obtained through the OpenBao CLI's OIDC login and run
`scripts/configure-openbao.py --flash-auth-only --prompt-admin-token` with the
kubeconfig, SSH key, recovery directory, and API origin shown by `--help`.
Enter the short-lived owner token at the terminal prompt; do not paste it into
a command argument or chat.

## Backup and recovery

A snapshot Job runs daily at 02:17 UTC. It signs in with a snapshot-only
Kubernetes service account, streams the Raft snapshot through `age` encryption,
and writes only ciphertext to a Longhorn volume replicated on three other
hosts. `scripts/snapshot-openbao.py` can also take an on-demand snapshot and
copy its ciphertext to the three backup hosts. An encrypted backup was
restored in an isolated, loopback-only OpenBao process using
`scripts/verify-restore.py`; the test checks a known KV v2 value and the OIDC
role before deleting that process and its temporary storage.

The bootstrap root token has been revoked. Two of the three Shamir shares are
needed to unseal after a restart. Each host keeps only its own share in a
host-bound systemd credential. The current hosts use systemd's host key, not a
TPM-bound key. The temporary all-share initialization artifact and its age key
were retired after the root token was revoked. The three hosts are now the only
unseal-share custodians. Losing two of them makes the snapshots unrecoverable
unless independently held share backups are arranged. The snapshot age private
key stays outside Git, Kubernetes, Terraform state, and backup hosts; copy it
to controlled offline storage. A copy on the same operator machine is not an
independent backup.

For a live check:

```bash
KUBECONFIG=/secure/operator-kubeconfig python3 scripts/verify-openbao.py
```

For an on-demand encrypted backup and three checksum-verified ciphertext
copies:

```bash
python3 scripts/snapshot-openbao.py \
  --kubeconfig /secure/operator-kubeconfig \
  --ssh-key /secure/operator-ssh-key \
  --snapshot-identity /secure/snapshot-identity.txt \
  --recovery-dir /secure/secret-manager-recovery \
  --inventory /secure/heteronetwork-inventory.json
```

For an isolated restore of a downloaded `.snap.age` file:

```bash
python3 scripts/verify-restore.py --restore \
  --kubeconfig /secure/operator-kubeconfig \
  --ssh-key /secure/operator-ssh-key \
  --known-hosts /secure/known_hosts \
  --recovery-dir /secure/secret-manager-recovery \
  --snapshot-identity /secure/snapshot-identity.txt \
  --snapshot /secure/secret-manager-recovery/openbao-raft-TIMESTAMP.snap.age
```

The restore probe is a deliberately non-sensitive test value. To make a new
probe, sign in as `owner` and run:

```bash
python3 scripts/verify-restore.py --prepare --prompt-admin-token \
  --kubeconfig /secure/operator-kubeconfig \
  --ssh-key /secure/operator-ssh-key \
  --recovery-dir /secure/secret-manager-recovery
```

Restore tests read two shares from separate custodian
hosts and authenticate with a read-only, short-lived Kubernetes identity. To
change the OIDC configuration, sign in as `owner` and run
`scripts/deploy-auth.py --prompt-admin-token` with the remaining arguments
shown by `--help`; the owner token is passed only through process memory.

Run `helm lint deploy/chart` and `python3 scripts/verify-chart.py` before
changing the chart. The repository's GitHub Actions workflow runs the same
checks and syntax validation.
