PYTHON ?= python3

.PHONY: test tools build verify reproducible
test:
	$(PYTHON) -B -m unittest discover -s tests -v
	cd vendor/passwall2 && $(PYTHON) -B -m unittest discover -s tests -v

tools:
	$(PYTHON) -B -m scripts.fetch_tools --latest

build:
	$(PYTHON) -B -m scripts.build

verify:
	$(PYTHON) -B -m scripts.verify

reproducible:
	$(PYTHON) -B -m scripts.reproducible
