# rpi-docker
Just a simple setup for an owncloud server running on my RaspberryPi

To run:
- Enable IPv6 in the docker daemon by adding the following lines to `/etc/docker/daemon.json`:
```json
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00:dead:beef:1000::/64",
  "experimental": true,
  "ip6tables": true
}
```
- Reboot the device.
- Run the following to install rclone: (used to make the owncloud data accesible to the other containers via WebDAV)
```bash
sudo mkdir -p /var/lib/docker-plugins/rclone/config
sudo mkdir -p /var/lib/docker-plugins/rclone/cache
docker plugin install rclone/docker-volume-rclone:arm64 args="-v" --alias rclone --grant-all-permissions
```
- (Optional) For Jellyfin hardware acceleration make sure to modify `/boot/config.txt` as follows:
```
# See /boot/overlays/README for all available options

gpu_mem=128  # <---- Make sure you have at least 128
...
...
dtoverlay=vc4-fkms-v3d,cma-512  # <---- Make sure this line is exactly like this
dtoverlay=rpivid-v4l2  # <---- Add this line 
...
...
```
- Make sure the file `traefik/acme.json` is empty and has permissions `600`
- Fill in your details in `.env`. Use `.env.example` as an example
- `./deploy.sh`
- Enable the docker service to run on boot.

The containers will spawn automatically when the docker service is started on each boot.
