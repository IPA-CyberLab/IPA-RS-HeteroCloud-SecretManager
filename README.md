# Hetero Secret Manager

OpenBao is deployed by Argo CD from `deploy/chart` onto the three dedicated
HeteroNetwork control-plane hosts. The chart includes a pinned, vendored
official OpenBao chart, local Raft volumes, cert-manager certificates, and a
namespace network policy. Host storage preparation and the admission policy
live in [HeteroNetwork](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork).

To validate a change without touching the cluster:

```bash
helm lint deploy/chart
python3 scripts/verify-chart.py
```

Once Argo CD has synced the release, verify the live placement and TLS status
with `KUBECONFIG=/secure/operator-kubeconfig python3 scripts/verify-openbao.py
--allow-sealed`. Do not initialize OpenBao until key custodians and an
independent recovery destination have been designated.

## Deployment and key custody

`openbao-0`, `openbao-1`, and `openbao-2` run only on `uc-k8sp1`, `uc-k8sp2`,
and `uc-k8s3p`, one server on each host. Required pod anti-affinity and the
three local PersistentVolumes ensure one Raft voter and one copy of the
encrypted database on each physical host. No Longhorn replica or other
application Pod is placed there. The existing Kubernetes control-plane and
network Pods remain; `uc-k8sp2` also runs the existing PostgreSQL HA etcd
voter until that topology is separately changed.

The official OpenBao Helm chart is pinned to `0.29.6`; the server image is
OpenBao `2.6.3` pinned by OCI digest. The `openbao` ClusterIP Service exposes
the TLS API to the Kubernetes cluster only. Its Raft port accepts traffic only
from the other OpenBao Pods. The internal CA and server certificate are issued
by cert-manager in the `openbao` namespace. The CA private key is a Kubernetes
Secret; it is a TLS trust anchor, not an OpenBao unseal key. The cert-manager
Secret must be backed up and access-restricted. Rotate the server Pods one at
a time after cert-manager renews the mounted TLS certificate, because OpenBao
does not automatically reload this chart's listener certificate.

The encrypted OpenBao barrier root key is held in the three Raft replicas.
This is distinct from the initial **root token** and from the Shamir **unseal
key shares**. Do not store the root token or plaintext unseal shares in Git,
Terraform state, Kubernetes Secrets, Pod environment variables, CI logs, or on
the same hosts as the Raft database. A 2-of-3 unseal threshold permits one
key holder to be unavailable. Initialization requires three designated PGP
public keys for the shares and a separate PGP public key for the initial root
token; no `operator init` is run until those recipients are fixed and an
independent recovery copy is arranged. Use `bao operator init -key-shares=3
-key-threshold=2 -pgp-keys=... -root-token-pgp-key=...` once against
`openbao-0`. Decrypt each share only with its holder. At every restart, each
OpenBao Pod needs two holders to enter their shares with the interactive
`bao operator unseal` prompt. Never pass a share as a CLI argument.

After initialization, configure short-lived admin authentication and
least-privilege policies, then revoke the initial root token. Raft replication
survives one host failure; it does not replace an independently stored,
encrypted Raft snapshot and key-custody backup. The snapshot and root-token
bootstrap are intentionally deferred until the key holders and backup
destination are selected. No application should write production secrets
before that recovery procedure is tested.

The live, credential-free infrastructure check is:

```bash
KUBECONFIG=/secure/operator-kubeconfig python3 scripts/verify-openbao.py --allow-sealed
```

After initializing and unsealing all three Pods, omit `--allow-sealed` to
require three Ready Pods and one active/two standby servers over verified TLS.
