FROM ubuntu:22.04

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y --fix-missing socat libreadline8 gdbserver 
RUN useradd -d /home/victim -m -p password1 -s /bin/bash victim

EXPOSE 1337

WORKDIR /home/victim

ADD mujs /home/victim/
ADD lib/ /home/victim/lib/
ADD exploit.js /home/victim/

RUN chmod 555 /home/victim/mujs
RUN chmod 440 /home/victim/exploit.js
RUN chown root:root /home/victim/mujs
RUN chown root:victim /home/victim/exploit.js

USER victim

CMD /bin/bash

#CMD socat tcp-listen:1337,reuseaddr,fork exec:"/home/victim/mujs -i exploit.js",rawer,pty,echo=0
