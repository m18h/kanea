# shop.hcl — everything for one project
spec_version = 1

project "shop" {
  description = "E-commerce storefront stack"

  # Optional: GitOps source for this project (see §10)
  git {
    url      = "https://github.com/example/shop-deploy.git"
    branch   = "main"
    path     = ".kanea/"
    auth_ref = "secret:shop/github-deploy-key"
  }

  notifications {
    telegram {
      chat_id   = "-1001234567890"
      token_ref = "secret:shop/telegram-bot"
    }
    # A Slack/Discord incoming-webhook URL is a credential in path form —
    # referenced, never inlined (R3, R5).
    slack { url_ref = "secret:shop/slack-webhook" }
    on       = ["deploy.failed", "service.unhealthy", "scale.*"]
    severity = "warning"
  }
}

# Storage resources may be declared here (project level) or in the server
# config (§8, §15.1). Volume blocks reference them by name.
storage "local-ssd" {
  type = "local"
}

storage "s3-media" {
  type     = "s3"
  bucket   = "shop-media"
  endpoint = "https://s3.eu-central-1.amazonaws.com"
  auth_ref = "secret:shop/s3-media"
  mode     = "ro"                           # mountpoint-s3; "rw" selects s3fs
}

service "web" {
  project     = "shop"
  description = "Storefront frontend (Next.js)"

  count = 3

  # Build from source instead of pulling (see §10)
  build {
    context    = "./web"
    # dockerfile = "Containerfile"        # optional override; auto-detected when
                                          # omitted (Containerfile, then Dockerfile)
    target     = "registry.example.com/shop/web"
    tag        = "${GIT_SHA_SHORT}"        # built-in variable
    cache_repo = "registry.example.com/shop/web-cache"
  }

  task "app" {
    image = "registry.example.com/shop/web:latest"   # or from build

    env = {
      NODE_ENV     = "production"
      DATABASE_URL = "secret:shop/database-url"      # secrets store ref
    }

    resources {
      cpu    = 500    # MHz
      memory = 512    # MiB
    }
  }

  network {
    port "http" { container = 3000 }

    # Also reachable at <node address>:8080, with or without a domain (R21,
    # §7.2.2). The label names the port above — there is no field here for a
    # container port number, so this cannot forward somewhere undeclared.
    publish "http" {
      host = 8080
      mode = "http"                              # "http" (default) | "tcp"
      ip_restriction { allow = ["192.168.0.0/16"] }
    }

    # Ingress beyond the default (§7.1): the project boundary is default-deny,
    # so a peer in another project is only reachable through an explicit edge.
    policy {
      allow_from = ["analytics/collector"]
    }
  }

  # North-south exposure: edge proxy + TLS + middleware
  expose {
    # domains optional — defaults to web.shop.<base_domain>
    domains = ["shop.example.com", "www.shop.example.com"]
    # Where the certificate comes from (R20, §7.3). Omit the block entirely and
    # the node's --tls-default decides; there is no field here for a path.
    tls { mode = "acme" }                        # acme | self-signed | provided | plaintext

    # Edge middleware (§7.2) — evaluated in order: IP restriction → rate limit → headers
    ip_restriction {
      allow = ["10.0.0.0/8", "203.0.113.0/24"]   # CIDRs; empty allow = world
      deny  = ["198.51.100.7/32"]                # deny wins over allow
    }

    rate_limit {
      requests = 100        # per window, token bucket
      window   = "1m"
      per      = "ip"       # ip | header:<name> | service
      burst    = 20
    }

    headers {
      # X-Forwarded-* is the edge's to set, and R16 rejects a spec that
      # touches it — those headers are the client identity everything else
      # is keyed on.
      request_set     = { X-Kanea-Tenant = "shop" }
      request_remove  = ["X-Internal-Debug"]
      response_set    = { Strict-Transport-Security = "max-age=63072000; includeSubDomains" }
      response_remove = ["Server", "X-Powered-By"]
    }
  }

  health_check "http" {
    type     = "http"
    path     = "/healthz"
    port     = "http"
    interval = "10s"
    timeout  = "2s"
    failures = 3
  }

  scaling {
    min = 2
    max = 10
    metric "cpu"        { target = 70 }     # percent of resources.cpu
    metric "rps"        { target = 500 }    # eBPF/L7 requests per sec
    metric "p95_latency_ms" { target = 800 }
    cooldown = "2m"
  }

  update {
    strategy     = "rolling"
    max_parallel = 1
    min_healthy  = "30s"
  }

  restart {
    attempts = 5
    backoff  = "10s,30s,1m,5m"
  }
}

service "api" {
  project     = "shop"
  description = "Storefront backend API"
  count       = 2

  task "api" {
    image = "registry.example.com/shop/api:0.9.1"   # image-only deploy — no git needed

    env = {
      # Service references (§7.1.1): interpolated to internal DNS names at
      # alloc start, validated at plan time; each implies a dependency edge.
      DATABASE_HOST = "${service.postgres.host}"        # → postgres.shop.kanea
      DATABASE_PORT = "${service.postgres.port.pg}"     # → 5432
      DATABASE_URL  = "secret:shop/database-url"
      ASSETS_ORIGIN = "http://${service.assets.host}"   # forward refs OK (order-independent)
    }

    resources {
      cpu    = 500
      memory = 256
    }
  }

  network {
    port "http" {
      container = 8080
    }
  }

  # Explicit start ordering on top of the implicit reference edges (§7.1.1)
  depends_on = ["postgres", "assets"]

  health_check "http" {
    type     = "http"
    path     = "/healthz"
    port     = "http"
    interval = "10s"
    timeout  = "2s"
    failures = 3
  }
}

service "postgres" {
  project     = "shop"
  description = "Primary database"
  count       = 1

  task "db" {
    image = "postgres:17@sha256:…"            # digest pinning recommended

    # Stock images routinely chown their data dir and drop to their own user at
    # startup. Workloads run with ALL capabilities dropped (§14, A05), so those
    # few must be requested explicitly — and only from the permitted set (R13).
    capabilities = ["CAP_CHOWN", "CAP_SETUID", "CAP_SETGID", "CAP_DAC_OVERRIDE"]

    resources {
      cpu    = 1000
      memory = 2048
    }
  }

  # internal only — no expose block
  network {
    port "pg" {
      container = 5432
    }
  }

  volume "data" {
    storage    = "local-ssd"                  # named storage resource (§8)
    mount_path = "/var/lib/postgresql/data"
  }
}

service "assets" {
  project = "shop"
  task "cdn" {
    image = "nginx:1.27-alpine"

    # Argument array, never a shell string (R12).
    command      = ["nginx", "-g", "daemon off;"]
    capabilities = ["CAP_CHOWN", "CAP_SETUID", "CAP_SETGID"]
  }
  volume "media" {
    storage    = "s3-media"                   # S3 bucket mounted via FUSE
    mount_path = "/usr/share/nginx/html/media"
    read_only  = true
  }
  network {
    port "http" { container = 80 }
  }
  # auto domain: assets.shop.<base_domain>
  expose {
    tls { mode = "acme" }
  }
}
