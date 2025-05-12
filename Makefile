# maven commands ------------------------------------------------------------------------
clean:
	./mvnw clean

build:
	./mvnw clean package

build-no-test:
	./mvnw clean package -Dmaven.test.skip=true

test:
	./mvnw clean test

install:
	./mvnw clean install
