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

Once Argo CD has synced the release, verify placement and TLS with
`KUBECONFIG=/secure/operator-kubeconfig python3 scripts/verify-openbao.py
--allow-sealed`.

## Deployment and key custody

`openbao-0`, `openbao-1`, and `openbao-2` run only on `uc-k8sp1`, `uc-k8sp2`,
and `uc-k8s3p`, one server on each host. Required pod anti-affinity and the
three local PersistentVolumes ensure one Raft voter and one copy of the
encrypted database on each physical host. No Longhorn replica or other
application Pod is placed there. The existing Kubernetes control-plane and
network Pods remain. The former PostgreSQL HA etcd voter on `uc-k8sp2` was
moved to `ichikawap1` before OpenBao was scheduled.

The official OpenBao Helm chart is pinned to `0.29.6`; the server image is
OpenBao `2.6.3` pinned by OCI digest. The `openbao` ClusterIP Service exposes
the TLS API to the Kubernetes cluster only. Its Raft port accepts traffic only
from the other OpenBao Pods. The internal CA and server certificate are issued
by cert-manager in the `openbao` namespace. The CA private key is a Kubernetes
Secret; it is a TLS trust anchor, not an OpenBao unseal key. The cert-manager
Secret must be backed up and access-restricted. Rotate the server Pods one at
a time after cert-manager renews the mounted TLS certificate, because OpenBao
does not automatically reload this chart's listener certificate.

The encrypted OpenBao barrier root key is replicated by Raft. This is distinct
from the initial **root token** and the three Shamir **unseal shares**. The
cluster uses a 2-of-3 threshold. One share is encrypted under each custodian
host's systemd host credential key, at
`/etc/heteronetwork/openbao-custody/unseal-share.cred`. The initial root token
and all three shares are also stored in one age-encrypted recovery artifact,
`openbao-init.json.age`, outside the cluster. Its recipient is the operator's
SSH public key; the matching private key must be stored separately and copied
to durable, access-controlled offline storage. Do not place plaintext shares
or tokens in Git, Terraform state, Kubernetes Secrets, environment variables,
or logs. The current hosts do not support TPM-bound systemd credentials, so
their encrypted shares are protected by host filesystem credentials and the
2-of-3 threshold; a separate offline copy is required for host-loss recovery.

Initialize and unseal over a verified TLS port-forward with
`scripts/bootstrap-openbao.py`. It checks the TLS CA, encrypts the init response
before writing it to disk, transfers each share through SSH into the host
credential store, reads back all three shares, and unseals all Pods with shares
from two distinct hosts. Re-running it uses the encrypted recovery artifact to
resume after an interruption or unseal after a restart:

```bash
read -rsp 'sudo password: ' HNN_IAC_BECOME_PASSWORD
export HNN_IAC_BECOME_PASSWORD
python3 scripts/bootstrap-openbao.py \
  --kubeconfig /secure/operator-kubeconfig \
  --ssh-key /secure/operator-ssh-key \
  --known-hosts /secure/known_hosts \
  --recovery-dir /secure/offline-recovery
unset HNN_IAC_BECOME_PASSWORD
```

The root token remains in the age-encrypted artifact. Before production secret
writes, configure short-lived admin authentication and least-privilege policies,
take an encrypted Raft snapshot to a separate recovery destination, test its
restore, and revoke the initial root token. Raft replication alone does not
replace an independent backup.

The live, credential-free infrastructure check is:

```bash
KUBECONFIG=/secure/operator-kubeconfig python3 scripts/verify-openbao.py --allow-sealed
```

After initializing and unsealing all three Pods, omit `--allow-sealed` to
require three Ready Pods and one active/two standby servers over verified TLS.
