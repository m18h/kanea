# shop.hcl — everything for one project
spec_version = 1

project "shop" {
  description = "E-commerce storefront stack"

  # Optional: GitOps source for this project (see §10)
  git {
    url      = "https://github.com/example/shop-deploy.git"
    branch   = "main"
    path     = ".kanea/"
    auth_ref = "secret:git/github-deploy-key"
  }

  notifications {
    telegram { chat_id = "-1001234567890" }   # bot token from secrets
    webhook  { url = "https://hooks.slack.com/services/…" }
    on       = ["deploy.failed", "service.unhealthy", "scale.*"]
  }
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
  }

  # North-south exposure: edge proxy + TLS + middleware
  expose {
    # domains optional — defaults to web.shop.<base_domain>
    domains = ["shop.example.com", "www.shop.example.com"]
    tls { letsencrypt = true }

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
      request_set     = { X-Forwarded-Proto = "https" }
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
  }
  volume "media" {
    storage    = "s3-media"                   # S3 bucket mounted via FUSE
    mount_path = "/usr/share/nginx/html/media"
    read_only  = true
  }
  # auto domain: assets.shop.<base_domain>
  expose {
    tls { letsencrypt = true }
  }
}
