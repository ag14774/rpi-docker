#!/usr/bin/env bash

docker build -t rootfsimage .
id=$(docker create rootfsimage true)
mkdir -p rootfs
docker export "$id" | tar -x -C rootfs
docker rm -vf "$id"
docker rmi rootfsimage

docker plugin create rclone_oidc .
docker plugin set rclone_oidc args='-v'
