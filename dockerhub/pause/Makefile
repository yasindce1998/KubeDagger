all: container push

build-pause-c:
	mkdir -p bin
	gcc -static -O3 pause.c -o bin/pause

container:
	mkdir -p bin
	cp ../../bin/pause bin/
	docker build -t yasindce1998/pause2:latest -t yasindce1998/pause2:3.2 .

login:
	docker login --username yasindce1998

push:
	docker push yasindce1998/pause2:latest
	docker push yasindce1998/pause2:3.2
