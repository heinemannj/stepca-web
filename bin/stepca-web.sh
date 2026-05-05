#!/usr/bin/env bash

AUTH_BACKEND=local uv run --frozen gunicorn \
  --preload \
  --bind="0.0.0.0:5000" \
  --log-level="debug" \
  --umask 007 \
  run:app
