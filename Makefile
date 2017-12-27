APXS =/usr/local/apache/bin/apxs

all: mod_logpost.c
        $(APXS) -Wc,-Wall -c mod_logost.c

install: all
        sudo $(APXS) -i -a -n logpost mod_logpost.la;\

clean:
        rm mod_dumpost.l*
        rm mod_dumpost.s*
