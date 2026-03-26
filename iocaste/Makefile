CC = $(shell xcrun --sdk iphoneos --find clang)
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
LDID = $(shell which ldid)

CFLAGS := -I./include -isysroot $(SDK) -arch armv7 -miphoneos-version-min=9.0
LDFLAGS := -L$(SDK)/usr/lib -lSystem -lc -framework CoreFoundation \
	-Wl,-sectcreate,__DATA,__stage3,./resources/stage3.js

SRC = $(wildcard src/*.c)

all: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o iocaste $^
	$(LDID) -S./resources/ents.xml iocaste

clean:
	@rm -rf iocaste
