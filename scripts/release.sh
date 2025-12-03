#!/usr/bin/env bash

# git tag, docker build and push

# set version from args if not, exit
if [ -z "$1" ]
  then
    echo "No version supplied (e.g. 1.0.0)"
    exit 1
fi

REPO=agessaman/meshinfo
VERSION=$1
# echo $CR_PAT | docker login ghcr.io -u USERNAME --password-stdin
git tag -a $VERSION -m "Version $VERSION" && git push --tags && \
sudo docker build -t ghcr.io/$REPO:$VERSION --platform=linux/amd64 . && \
echo "sudo docker push ghcr.io/$REPO:$VERSION"
