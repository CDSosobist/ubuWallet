.PHONY: run test check install

run:
	./run.sh

test:
	python3 -m unittest discover -s tests -v

check:
	python3 -m compileall -q shkatulka tests

install:
	./install.sh
