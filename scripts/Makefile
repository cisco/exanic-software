PREFIX=/usr/local
BINDIR=$(DESTDIR)$(PREFIX)/bin

SCRIPTS=exasock

install: $(SCRIPTS)
	install -d $(BINDIR)
	install -m 0755 -D $(SCRIPTS) $(BINDIR)

uninstall:
	rm -f $(foreach file,$(SCRIPTS),$(BINDIR)/$(file))
