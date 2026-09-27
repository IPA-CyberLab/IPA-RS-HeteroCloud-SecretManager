#!/usr/bin/env python3
"""Fail if the rendered release loses its dedicated, encrypted Raft layout."""

import hashlib
import os
from pathlib import Path
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[1]
NODES = {'uc-k8sp1', 'uc-k8sp2', 'uc-k8s3p'}
CHART_SHA256 = '8079e985bdf608f965ada59c70051693d14dd2454ac16311229f367d0c48c4b9'
SERVER_DIGEST = 'sha256:a60afafda36337abe833c4a63894bf1095098f29abea4091e7e555a33dd52889'


def main():
    archive = ROOT / 'deploy/chart/charts/openbao-0.29.6.tgz'
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == CHART_SHA256
    rendered = subprocess.check_output(
        [os.environ.get('HELM', 'helm'), 'template', 'openbao', str(ROOT / 'deploy/chart'),
         '--namespace', 'openbao', '--skip-tests'], text=True,
    )
    objects = [obj for obj in yaml.safe_load_all(rendered) if obj]
    by_kind = {(obj['kind'], obj['metadata']['name']): obj for obj in objects}

    namespace = by_kind['Namespace', 'openbao']
    assert namespace['metadata']['labels']['pod-security.kubernetes.io/enforce'] == 'restricted'
    storage = by_kind['StorageClass', 'openbao-local']
    assert storage['volumeBindingMode'] == 'WaitForFirstConsumer'
    assert storage['reclaimPolicy'] == 'Retain'
    for node in NODES:
        volume = by_kind['PersistentVolume', f'openbao-{node}']['spec']
        assert volume['persistentVolumeReclaimPolicy'] == 'Retain'
        assert volume['local']['path'] == '/var/lib/openbao/raft'
        assert volume['nodeAffinity']['required']['nodeSelectorTerms'][0]['matchExpressions'][0]['values'] == [node]

    cert = by_kind['Certificate', 'openbao-server']['spec']
    assert cert['secretName'] == 'openbao-server-tls'
    assert '*.openbao-internal.openbao.svc.cluster.local' in cert['dnsNames']
    statefulset = by_kind['StatefulSet', 'openbao']['spec']
    pod = statefulset['template']['spec']
    server = pod['containers'][0]
    assert statefulset['replicas'] == 3
    assert statefulset['persistentVolumeClaimRetentionPolicy'] == {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}
    assert statefulset['volumeClaimTemplates'][0]['spec']['storageClassName'] == 'openbao-local'
    assert pod['nodeSelector'] == {'heteronetwork.io/control-plane-only': 'true'}
    assert pod['serviceAccountName'] == 'openbao'
    assert len(pod['affinity']['podAntiAffinity']['requiredDuringSchedulingIgnoredDuringExecution']) >= 1
    assert server['image'].endswith('@' + SERVER_DIGEST)
    assert any(v['name'] == 'userconfig-openbao-server-tls' and v['secret']['secretName'] == 'openbao-server-tls'
               for v in pod['volumes'])
    assert server['securityContext']['allowPrivilegeEscalation'] is False
    assert 'ALL' in server['securityContext']['capabilities']['drop']
    assert pod['securityContext']['runAsNonRoot'] is True
    assert by_kind['NetworkPolicy', 'openbao-server']['spec']['policyTypes'] == ['Ingress']
    print(f'validated {len(objects)} rendered resources, three dedicated Raft volumes and TLS server pods')


if __name__ == '__main__':
    main()
