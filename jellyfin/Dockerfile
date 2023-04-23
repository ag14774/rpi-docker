FROM jellyfin/jellyfin

ARG host_video_gid

RUN apt-get update && apt-get install cron
COPY ./backup_script.sh /backup_script.sh
RUN chmod +x /backup_script.sh
RUN (crontab -l 2>/dev/null; echo "0 0 * * 0 /backup_script.sh > /proc/1/fd/1 2>/proc/1/fd/2") | crontab -

RUN groupmod -g ${host_video_gid} video
RUN useradd -ms /bin/bash abc
RUN usermod -a -G video abc

USER abc
