PREFIX ?= /usr/local
BINARY = ota-touchid
BUILD_DIR = .build/release

.PHONY: build install uninstall test clean

build:
	swift build -c release --disable-sandbox

install: build
	install -d $(PREFIX)/bin
	install -m 755 $(BUILD_DIR)/$(BINARY) $(PREFIX)/bin/$(BINARY)

uninstall:
	rm -f $(PREFIX)/bin/$(BINARY)

test:
	swift test

clean:
	swift package clean
