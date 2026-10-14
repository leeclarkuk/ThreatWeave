# Northwind Shop (fictional demonstration system)

A small web shop. `web` terminates TLS and proxies to `api`. `api` talks to Postgres and to the
internal `inventory` service, which keeps stock levels in Redis. Only `web` is published.

This directory exists to demonstrate ThreatWeave. It is not a real system.
