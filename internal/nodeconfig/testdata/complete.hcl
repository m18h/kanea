# /etc/kanea/kanea.hcl - the node's one configuration file.
#
# Every attribute is optional. A value shown here is the default unless its
# comment says otherwise; an attribute left out means that default. kanead
# and kanea-edge read the file once, at startup: edit it, then restart them.

data_dir      = "/var/lib/kanea"         # state, the master key, volumes
alloc_log_dir = "/var/log/kanea/allocs"  # per-alloc workload logs
log_level     = "info"                   # debug | info | warn | error
base_domain   = "apps.example.com"       # no default; gives <service>.<project>.apps.example.com

# Node-wide spec variables: defaults every spec on this node may reference as
# ${name}. A spec's own variables block wins. Primitives only, never secrets:
# the stanza is served to any authenticated caller.
variables {
  domain = "home.lan"
}

# Every listener the node opens.
bind {
  api_socket = "/run/kanea/kanead.sock"  # the CLI's unix socket
  api_addr   = "192.168.1.10:8600"       # no default; omit for socket-only

  # How the API/dashboard listener is secured:
  #   acme        a public certificate; requires api_domain
  #   self-signed the node CA; names api_domain, else api_addr's host
  #   provided    the api_cert/api_key pair, loaded once
  #   plaintext   explicit HTTP; beyond loopback it is logged loudly
  # Unset: a pair means provided, loopback means plaintext, anything else
  # is refused.
  api_tls    = "provided"
  api_domain = "kanea.example.com"
  api_cert   = "/etc/kanea/tls/api.crt"
  api_key    = "/etc/kanea/tls/api.key"

  edge_http  = ":80"                     # the edge's public HTTP listener
  edge_https = ":443"                    # "off" serves plaintext only
}

auth {
  insecure_cookies = false               # true only behind plain HTTP

  # Single sign-on. No default: without an issuer, password login only.
  oidc {
    issuer        = "https://auth.example.com/realms/kanea"
    client_id     = "kanea"
    client_secret = "secret:shared/oidc"  # omit for a public PKCE client
    redirect_url  = "https://kanea.example.com/v1/auth/oidc/callback"
    scopes        = ["profile", "email"]  # beyond openid; [] requests none
    role_claim    = "groups"
    admin_claims  = ["kanea-admins"]
    viewer_claims = ["kanea-viewers"]
  }

  # Directory login. No default: without a url, no LDAP.
  ldap {
    url            = "ldaps://ldap.example.com"
    bind_dn        = "cn=kanea,ou=services,dc=example,dc=com"
    bind_password  = "secret:shared/ldap-bind"
    user_base_dn   = "ou=people,dc=example,dc=com"
    user_filter    = "(uid=%s)"
    group_base_dn  = "ou=groups,dc=example,dc=com"
    group_filter   = "(member=%s)"
    admin_groups   = ["cn=kanea-admins,ou=groups,dc=example,dc=com"]
    viewer_groups  = ["cn=kanea-viewers,ou=groups,dc=example,dc=com"]
    ca_file        = "/etc/kanea/tls/ldap-ca.pem"
  }
}

audit {
  retention = "2160h"                    # 90 days; "0" keeps entries forever
}

dashboard {
  enabled = true
  origins = []                           # extra Origins allowed to open the live websocket
}

# kanead is the IPAM: these are fixed when the node is installed. node_cidr
# must sit inside cluster_cidr, and neither may overlap service_cidr.
network {
  driver       = "ebpf"                  # or "netns": development only, no policy, no service LB
  node_cidr    = "10.244.0.0/24"         # alloc addresses
  cluster_cidr = "10.244.0.0/16"         # routed range, masqueraded on egress
  service_cidr = "10.201.0.0/16"         # service frontends
  # The IPv6 trio comes together or not at all. No defaults.
  node_cidr6    = "fd00:10:244::/64"
  cluster_cidr6 = "fd00:10:244::/56"
  service_cidr6 = "fd00:10:201::/112"
  bpf_dir       = "/sys/fs/bpf/kanea"    # pinned maps, programs and links
}

dns {
  listen    = "10.244.0.1:53"            # default: the node CIDR's .1; "off" disables
  upstreams = ["1.1.1.1", "9.9.9.9:53"]  # default: the host's resolv.conf
}

storage {
  volume_dir = "/var/lib/kanea/volumes"  # default: <data_dir>/volumes
  # Empty by default: no spec can mount a host directory until a permitted
  # parent is named here.
  allowed_host_paths = ["/srv/kanea"]
}

images {
  pull_policy = "if-not-present"         # or "never"

  # Image garbage collection. An image is deleted only when nothing
  # references it, it is older than min_age, and it is outside the newest
  # `keep` of a repository something still uses.
  gc {
    enabled  = true
    interval = "12h"                     # floor 10m
    min_age  = "48h"                     # floor 1h
    keep     = 2
  }
}

containerd {
  socket = "/run/kanea/containerd.sock"
}

metrics {
  interval       = "5s"
  containerd_url = "http://127.0.0.1:1338/v1/metrics"  # "off" disables cgroup metrics
  edge_url       = "http://127.0.0.1:8601/metrics"     # "off" disables the L7 signal
}

scaling {
  enabled = true                         # act on the scaling policies services declare
}

builds {
  buildkit_addr     = "unix:///var/lib/kanea/buildkit/run/buildkitd.sock"  # "off" disables GitOps and builds
  log_dir           = "/var/lib/kanea/builds"                              # default: <data_dir>/builds
  registry_addr     = "127.0.0.1:5100"   # the internal build registry; "off" disables
  insecure_registry = false              # push built images over plain HTTP
}

gitops {
  sync_interval = "2m"                   # how often git sources are polled
}

# External secret providers. `secrets` holds the schedule; each `provider`
# block maps values from one provider into this node's store. Credentials are
# 0600 files on the node, never inline. A rotated credential file is picked
# up without a restart; a changed block needs one.
secrets {
  sync_interval = "5m"                   # floor 30s
}

provider "doppler" "ci" {
  token_file = "/etc/kanea/secrets/doppler.token"
  project    = "backend"
  config     = "prd"
  allow      = ["shop", "shared"]        # the scopes its mappings may write into
  sync {
    name = "DATABASE_URL"
    to   = "shop/db-url"
  }
}

provider "vault" "infra" {
  address    = "https://vault.internal:8200"
  token_file = "/etc/kanea/secrets/vault.token"
  mount      = "kv"
  allow      = ["media"]
  sync {
    path  = "apps/media"
    field = "s3_secret_key"
    to    = "media/s3-secret"
  }
}

tls {
  # Where an exposed service's certificate comes from when its spec does not
  # say: acme | self-signed | provided | plaintext.
  default_mode = "acme"
  ca_name      = "home.lan"              # default: base_domain, else the hostname
}

# Certificates the operator put on this node. A spec asks for one by name and
# never names a path. What a certificate covers is read from its own SANs. A
# renewed pair is picked up without a restart; a changed block needs one.
certificate "shop" {
  cert  = "/etc/kanea/tls/shop.crt"      # leaf + intermediates, PEM
  key   = "/etc/kanea/tls/shop.key"
  allow = ["shop"]                       # projects that may claim it
}

acme {
  email          = "ops@example.com"     # no default; without it no certificate is requested from a CA
  directory      = "production"          # or "staging", or a directory URL
  ca_bundle_file = "/etc/kanea/tls/acme-ca.pem"  # no default; for a private CA
  verify_url     = "http://127.0.0.1:80" # where kanead reaches its own edge

  # RFC 2136 dynamic updates: enables DNS-01 and wildcards. No defaults.
  dns01 {
    server         = "ns1.example.com:53"
    zone           = "example.com"
    tsig_key       = "kanea-acme"
    tsig_secret    = "secret:shared/tsig"
    tsig_algorithm = "hmac-sha256."
  }
}

# The ingress proxy. kanead publishes the two files; kanea-edge reads them.
edge {
  routes_file      = "/run/kanea-edge/routes.json"  # "off" stops kanead publishing routes
  certs_file       = "/run/kanea-edge/certs.json"
  certs_group      = "kanea-edge"        # default: owner only; `kanea init` writes this
  status_addr      = "127.0.0.1:8601"    # health and metrics; "off" disables
  poll_interval    = "1s"
  drain_timeout    = "15s"
  body_timeout     = "5m"                # "0" disables
  upstream_timeout = "1m"
  functions_port   = 0                   # 0 disables the path-routed functions listener
  security_headers = true
  rate_limit_buckets = 65536
  memory_limit     = "128MiB"            # no default; a soft GOMEMLIMIT
  log_level        = "info"

  # Which node ports a spec may publish.
  publish {
    ports         = "1024-65535"         # "off" disables publishing
    max_conns     = 1024                 # ceiling across every published tcp port
    drain_timeout = "60s"                # default: drain_timeout above
  }
}

notifications {
  allow_private   = false                # targets on private or loopback addresses
  allow_http      = false                # plain-http targets
  event_retention = 500
}

# State replication. A destination saved from the dashboard wins over this
# stanza; this is the fallback, and the only source a blank node can restore
# from.
backup {
  dir = "/mnt/backup/kanea"
  snapshot_interval = "6h"
  segment_interval  = "1m"               # bounds the recovery point
  retention         = 7                  # snapshots kept
  restore_if_empty  = false              # restore the newest archive onto a node with no state

  s3 {
    url        = "s3://kanea-state/prod/node-a"
    endpoint   = "https://s3.eu-central-1.amazonaws.com"
    region     = "eu-central-1"
    access_key = "AKIAEXAMPLE"
    secret_key = "secret:shared/backup-s3"
    path_style = true
  }
}

upgrade {
  repo              = "m18h/kanea"       # where releases are fetched from
  require_signature = false              # refuse a release whose cosign signature cannot be verified
}

# Device and socket grants. A spec asks for a grant by name; the node resolves
# it. `allow` is required: a grant nobody is named for is a typo.
device "gpu" {
  nodes = ["/dev/dri/renderD128"]        # device node paths, resolved per alloc
  allow = ["media"]                      # projects that may request it
  mode  = "rw"                           # cgroup permissions
}

# A socket grant is root on the node for whoever holds it.
socket "containerd" {
  path  = "/run/kanea/containerd.sock"
  allow = ["ops"]
}
