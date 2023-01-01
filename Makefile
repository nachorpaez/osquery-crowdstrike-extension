all: build

APP_NAME = crowdstrike.ext
PKGDIR_TMP = ${TMPDIR}golang

.pre-build:
	mkdir -p build

init:
	go mod init github.com/nachorpaez/osquery-crowdstrike-extension

download:
	go mod download

clean:
	rm -rf build/
	rm -rf ${PKGDIR_TMP}_darwin

test:
	go test -v ./... 

build: .pre-build
	GOOS=darwin GOARCH=amd64 go build -o build/${APP_NAME}-amd64 -pkgdir ${PKGDIR_TMP}
	GOOS=darwin GOARCH=arm64 go build -o build/${APP_NAME}-arm64 -pkgdir ${PKGDIR_TMP}
	lipo -create -output build/${APP_NAME} build/${APP_NAME}-amd64 build/${APP_NAME}-arm64

osqueryi: build
	sleep 2
	@sudo osqueryi --extension=build/crowdstrike.ext --allow_unsafe