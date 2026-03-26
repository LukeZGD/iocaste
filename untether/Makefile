CC = $(shell xcrun --sdk iphoneos --find clang)
STRIP = $(shell xcrun --sdk iphoneos --find strip)
LDID = $(shell which ldid)

SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
CFLAGS = -isysroot $(SDK) -arch armv7 -I./include -miphoneos-version-min=9.0 
LDFLAGS = -L$(SDK)/usr/lib -lc -lSystem -framework CoreFoundation -dynamiclib

SRC = $(wildcard src/*.c)

all: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o ./iocaste.dylib $^
	$(LDID) -S ./iocaste.dylib

clean:
	@rm -rf ./iocaste.dylib
	@rm -rf *.o
