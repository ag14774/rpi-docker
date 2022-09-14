# rpi-docker
Just a simple setup for an owncloud server running on my RaspberryPi

To run:
- Enable IPv6 in the docker daemon by adding the following lines to `/etc/docker/daemon.json`:
```json
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/8",
  "experimental": true,
  "ip6tables": true
}
```
- Reboot the device.
- Make sure the file `traefik/acme.json` is empty and has permissions `600`
- Fill in your details in `.env`. Use `.env.example` as an example
- Download your `credentials.json` file for Google OAuth using `console.cloud.google.com` and place it in `cron/duplicity/credentials.json`.
- `./deploy.sh`
- Enable the docker service to run on boot.

The containers will spawn automatically when the docker service is started on each boot.
