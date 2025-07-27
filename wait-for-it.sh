#!/usr/bin/env bash

set -e

host="$1"
port="$2"
shift 2

timeout=30
start_time=$(date +%s)

echo "Waiting for $host:$port to be available..."

while ! nc -z "$host" "$port"; do
  sleep 1
  now=$(date +%s)
  elapsed=$(( now - start_time ))
  if [ $elapsed -ge $timeout ]; then
    echo "Timeout waiting for $host:$port"
    exit 1
  fi
done

echo "$host:$port is available, executing command..."

exec "$@"
