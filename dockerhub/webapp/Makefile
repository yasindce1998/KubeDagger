all: container push

container:
	mkdir -p bin
	cp ../../bin/webapp bin/
	docker build -t yasindce1998/webapp:latest .

login:
	docker login --username yasindce1998

push:
	docker push yasindce1998/webapp:latest
