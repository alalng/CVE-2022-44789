#!/bin/sh

docker build . -t mujs_poc && \
	docker run -p 1337:1337 -it mujs_poc
