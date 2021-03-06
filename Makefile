GOPATH ?= ${shell go env GOPATH}


# This is how we want to name the binary output
BINARY=km-reverse-proxy
#
# # These are the values we want to pass for Version and BuildTime
VERSION=0.1.0

all:
	cd $(GOPATH)/src; go install github.com/cviecco/km-reverse-proxy/cmd/*
	#cd cmd/km-reverse-proxy; go build


get-deps:
	go get -t ./...

clean:
	rm -f bin/*
	rm -f km-reverse-proxy-*.tar.gz
	rm -f cmd/km-reverse-proxy/km-reverse-proxy

${BINARY}-${VERSION}.tar.gz:
	mkdir ${BINARY}-${VERSION}
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" authnHandler/ ${BINARY}-${VERSION}/authnHandler/
	rsync -av --exclude="*.yml" --exclude="*.pem" --exclude="*.out" --exclude="*.key" --exclude="*.txt"  cmd/ ${BINARY}-${VERSION}/cmd/
	rsync -av  misc/ ${BINARY}-${VERSION}/misc/
	cp LICENSE Makefile km-reverse-proxy.spec README.md ${BINARY}-${VERSION}/
	tar -cvzf ${BINARY}-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/

rpm:    ${BINARY}-${VERSION}.tar.gz
	rpmbuild -ta ${BINARY}-${VERSION}.tar.gz

tar:    ${BINARY}-${VERSION}.tar.gz


format:
	gofmt -s -w .

format-imports:
	goimports -w .

test:	
	go test ./...

testold:
	@find * -name '*_test.go' |\
	sed -e 's@^@github.com/cviecco/km-reverse-proxy/@' -e 's@/[^/]*$$@@' |\
	sort -u | xargs -r go test
