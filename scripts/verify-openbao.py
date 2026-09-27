#!/usr/bin/env python3
"""Verify OpenBao's dedicated placement, TLS and three-member HA state."""
import argparse
import json
import subprocess
import sys

NODES = {'uc-k8sp1', 'uc-k8sp2', 'uc-k8s3p'}


def kubectl(*args, check=True):
    result = subprocess.run(
        ['kubectl', '--request-timeout=15s', *args], text=True,
        capture_output=True, timeout=30,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result


def resource(kind, *args):
    return json.loads(kubectl('get', kind, *args, '-o', 'json').stdout)


def condition_ready(item):
    return any(c['type'] == 'Ready' and c['status'] == 'True'
               for c in item.get('status', {}).get('conditions', []))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--allow-sealed', action='store_true',
                        help='Validate deployed infrastructure before key initialization')
    args = parser.parse_args()

    namespace = resource('namespace', 'openbao')
    assert namespace['metadata']['labels']['pod-security.kubernetes.io/enforce'] == 'restricted'
    certificate = resource('certificate', 'openbao-server', '-n', 'openbao')
    assert condition_ready(certificate), 'OpenBao TLS certificate is not Ready'
    statefulset = resource('statefulset', 'openbao', '-n', 'openbao')
    assert statefulset['spec']['replicas'] == 3
    pods = resource('pods', '-A')['items']
    openbao = sorted((p for p in pods if p['metadata']['namespace'] == 'openbao'
                      and p['metadata']['name'] in ('openbao-0', 'openbao-1', 'openbao-2')),
                     key=lambda p: p['metadata']['name'])
    assert len(openbao) == 3, f'Expected three OpenBao Pods, found {len(openbao)}'
    assert {p['spec']['nodeName'] for p in openbao} == NODES, 'OpenBao is not spread across its three dedicated hosts'
    for pod in openbao:
        assert pod['status']['phase'] == 'Running', (pod['metadata']['name'], pod['status']['phase'])
        assert pod['spec']['serviceAccountName'] == 'openbao'
        assert pod['spec']['nodeSelector'] == {'heteronetwork.io/control-plane-only': 'true'}

    expected_essential = {'kube-system', 'kube-flannel'}
    for pod in pods:
        if pod['spec'].get('nodeName') in NODES:
            assert pod['metadata']['namespace'] in expected_essential or pod in openbao, (
                'Unexpected workload on a dedicated OpenBao host', pod['metadata']['namespace'], pod['metadata']['name'])

    claims = resource('persistentvolumeclaims', '-n', 'openbao')['items']
    assert len(claims) == 3 and all(c['status']['phase'] == 'Bound' for c in claims), 'Raft PVCs are not all bound'
    pvs = {p['metadata']['name']: p for p in resource('persistentvolumes')['items']}
    for claim in claims:
        pv = pvs[claim['spec']['volumeName']]
        assert pv['spec']['storageClassName'] == 'openbao-local'
        assert pv['spec']['persistentVolumeReclaimPolicy'] == 'Retain'
        assert pv['spec']['local']['path'] == '/var/lib/openbao/raft'
        assert pv['spec']['nodeAffinity']['required']['nodeSelectorTerms'][0]['matchExpressions'][0]['values'][0] in NODES

    states = []
    for pod in openbao:
        name = pod['metadata']['name']
        command = ('BAO_ADDR=https://' + name + '.openbao-internal.openbao.svc.cluster.local:8200 '
                   'BAO_CACERT=/openbao/userconfig/openbao-server-tls/ca.crt bao status -format=json')
        result = kubectl('-n', 'openbao', 'exec', name, '--', '/bin/sh', '-c', command, check=False)
        if result.returncode not in (0, 2):
            raise RuntimeError(name + ': TLS/status check failed: ' + result.stderr.strip())
        try:
            state = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(name + ': invalid status response') from exc
        mode = ('active' if state.get('is_self') is True and state.get('active_time')
                else 'standby' if state.get('leader_address') and state.get('cluster_id')
                else None)
        states.append({'pod': name, 'initialized': state.get('initialized'),
                       'sealed': state.get('sealed'), 'ha_enabled': state.get('ha_enabled'),
                       'ha_mode': mode, 'cluster_id': state.get('cluster_id'),
                       'leader_address': state.get('leader_address'),
                       'raft_committed_index': state.get('raft_committed_index')})

    if not args.allow_sealed:
        assert all(s['initialized'] and not s['sealed'] and s['ha_enabled'] for s in states), states
        assert sorted(s['ha_mode'] for s in states) == ['active', 'standby', 'standby'], states
        assert len({s['cluster_id'] for s in states}) == 1 and all(s['cluster_id'] for s in states), states
        assert len({s['leader_address'] for s in states}) == 1, states
        assert all((s['raft_committed_index'] or 0) > 0 for s in states), states
        assert statefulset['status'].get('readyReplicas') == 3, 'OpenBao StatefulSet is not Ready'

    print(json.dumps({'nodes': sorted(NODES), 'tls_ready': True,
                      'raft_volumes_bound': 3, 'status': states,
                      'all_unsealed': all(s['initialized'] and not s['sealed'] for s in states)}))


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
