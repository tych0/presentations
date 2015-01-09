all:
	git submodule update --init

%:
	mkdir -p $@
	cp -r skel/* $@
	git submodule add gh:hakimel/reveal.js $@/reveal.js -b 3.0.0
	git add $@
