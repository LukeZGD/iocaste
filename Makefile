all:
	$(MAKE) -C iocaste all
	$(MAKE) -C untether all

clean:
	$(MAKE) -C iocaste clean
	$(MAKE) -C untether clean
	@rm -rf ./iocaste.tar
	@rm -rf ./staging

deb:
	@rm -rf ./staging
	@mkdir -p ./staging/DEBIAN
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/usr/lib
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/usr/bin

	@cp -a ./iocaste/iocaste ./staging/usr/bin/iocaste
	@cp -a ./untether/iocaste.dylib ./staging/usr/lib/iocaste.dylib

	@cp -a ./resources/control ./staging/DEBIAN/control
	@cp -a ./resources/postinst ./staging/DEBIAN/postinst
	@cp -a ./resources/prerm ./staging/DEBIAN/prerm

	@chmod 0755 ./staging/DEBIAN/prerm
	@chmod 0755 ./staging/DEBIAN/postinst
	@chmod 6755 ./staging/usr/bin/iocaste
	@chmod 0755 ./staging/usr/lib/iocaste.dylib
	dpkg-deb -Znone --root-owner-group --build ./staging ./com.staturnz.iocaste_1.0_iphoneos-arm.deb
	@chmod 0755 ./com.staturnz.iocaste_1.0_iphoneos-arm.deb
	@chown 501:20 ./com.staturnz.iocaste_1.0_iphoneos-arm.deb
	@chmod -R 0755 ./staging
	@chown -R 501:20 ./staging

tar:
	@rm -rf ./staging
	@mkdir -p ./staging
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/usr/bin
	@umask u=rwx,g=rx,o=rx && mkdir -p ./staging/usr/lib
	@cp -a ./iocaste/iocaste ./staging/usr/bin/iocaste
	@cp -a ./untether/iocaste.dylib ./staging/usr/lib/iocaste.dylib
	@chmod 0755 ./staging/usr/bin/iocaste
	@chmod 0755 ./staging/usr/lib/iocaste.dylib

	@find ./staging -name '.DS_Store' -type f -delete
	cd ./staging && COPYFILE_DISABLE=1 tar -c --no-xattrs -f ../iocaste.tar ./*
	@chmod 0755 ./iocaste.tar
	@chown 501:20 ./iocaste.tar
	@chmod -R 0755 ./staging
	@chown -R 501:20 ./staging

package: clean all deb tar
