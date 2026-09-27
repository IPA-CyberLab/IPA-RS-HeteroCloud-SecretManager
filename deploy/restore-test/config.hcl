ui = false
api_addr = "http://127.0.0.1:18200"
cluster_addr = "http://127.0.0.1:18201"
listener "tcp" {
  address = "127.0.0.1:18200"
  cluster_address = "127.0.0.1:18201"
  tls_disable = true
}
storage "raft" {
  path = "/tmp/openbao-restore-test/raft"
  node_id = "isolated-restore-test"
}
