FROM jellyfin/jellyfin

ARG host_video_gid

RUN groupmod -g ${host_video_gid} video
RUN useradd -ms /bin/bash abc
RUN usermod -a -G video abc

USER abc
