# rpi-docker
Just a simple setup for an owncloud server running on my RaspberryPi

To run:
- Make sure the file `traefik/acme.json` is empty and has permissions `600`
- Fill in your details in `.env`
- `docker-compose up -d`
- Enable the docker service to run on boot.

The containers will spawn automatically when the docker service is started on each boot.
