# Hetero Secret Manager

Hetero Secret Manager is the OpenBao service for HeteroCloud. Its native UI is
at <https://secrets.heterocloud.mizuame.app/ui/>. Select **OIDC**, then enter
`users` for a personal vault or `owner` for the system owner. Keycloak handles
sign-in. The `owner` role is bound to one existing Keycloak subject; ordinary
users can only read and write `secret/data/users/<their entity ID>/*`.

The deployment is GitOps-managed through the OpenBao Argo CD application in
[HeteroNetwork](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork).
`deploy/chart` pins the official OpenBao chart, the server image, TLS, the
public route, network policy, and backup CronJob. The three Raft voters each
have an encrypted local disk on `uc-k8sp1`, `uc-k8sp2`, or `uc-k8s3p`. These
control-plane hosts admit no other application workloads. The service is only
reachable through its TLS Kubernetes Service and the HeteroCloud gateway. The
public gateway selects the current Raft leader via OpenBao's Kubernetes
service-registration label so writes and following reads reach the same voter.

## Backup and recovery

A snapshot Job runs daily at 02:17 UTC. It signs in with a snapshot-only
Kubernetes service account, streams the Raft snapshot through `age` encryption,
and writes only ciphertext to a Longhorn volume replicated on three other
hosts. `scripts/snapshot-openbao.py` can also take an on-demand snapshot and
copy its ciphertext to the three backup hosts. The latest on-demand backup was
restored in an isolated, loopback-only OpenBao process using
`scripts/verify-restore.py`; the test checks a known KV v2 value and the OIDC
role before deleting that process and its temporary storage.

The bootstrap root token has been revoked. Two of the three Shamir shares are
needed to unseal after a restart. Each host keeps only its own share in a
host-bound systemd credential. The encrypted initialization artifact contains
all three shares for disaster recovery; it uses a **different** age key from
the snapshot backups. Keep both private age identities outside Git, Kubernetes,
Terraform state, and routine backup hosts. Copy the recovery identity to
controlled offline storage before relying on it for host-loss recovery. A
single operator machine holding the identities is not an independent offline
copy.

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
  --recovery-identity /secure/recovery-identity.txt \
  --recovery-dir /secure/secret-manager-recovery \
  --snapshot-identity /secure/snapshot-identity.txt \
  --snapshot /secure/secret-manager-recovery/openbao-raft-TIMESTAMP.snap.age
```

The restore probe is a deliberately non-sensitive test value. The first probe
is created with `scripts/verify-restore.py --prepare` before the bootstrap root
token is revoked. Later restore tests authenticate with a read-only,
short-lived Kubernetes identity. To change the OIDC configuration after root
token revocation, sign in as `owner` and run `scripts/deploy-auth.py
--prompt-admin-token` with the remaining arguments shown by `--help`; the
owner token is passed only through process memory.

Run `helm lint deploy/chart` and `python3 scripts/verify-chart.py` before
changing the chart. The repository's GitHub Actions workflow runs the same
checks and syntax validation.
