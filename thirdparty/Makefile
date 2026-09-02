all:
	@if [ "$$(uname -s)" = "Darwin" ] && find mbedtls -maxdepth 1 -name '*.o' -exec file {} + 2>/dev/null | grep -vq 'Mach-O'; then \
		echo "  CLEAN mbedtls (rebuilding stale object files)"; \
		$(MAKE) -C mbedtls clean; \
	fi
	$(MAKE) -C mbedtls all

clean:
	# this is a waste of time. Uncomment if you make changes to mbedtls
	#cd mbedtls; make clean;	