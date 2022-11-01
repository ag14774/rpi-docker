# rpi-docker
Just a simple setup for an owncloud server running on my RaspberryPi

To run:
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
- Fill in your details in `config.json`. Use `config.json.example` as an example.
- `python deploy.py` (If this step fails, reboot and try again)
- Reboot

The containers will spawn automatically when the docker service is started on each boot.
