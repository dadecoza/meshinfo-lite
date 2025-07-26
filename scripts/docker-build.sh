#!/usr/bin/env bash

# build

# Get version from git if not provided
if [ -z "$1" ]; then
  # Get the latest git tag
  LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
  # Get current commit hash
  COMMIT_HASH=$(git rev-parse --short HEAD)
  VERSION="${LATEST_TAG}-${COMMIT_HASH}"
  echo "Using git-based version: $VERSION"
else
  VERSION=$1
  echo "Using provided version: $VERSION"
fi

REPO=agessaman/meshinfo

docker build -t $REPO:$VERSION --platform=linux/amd64 .
