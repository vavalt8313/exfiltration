# Makefile for Python client/server build & execution with extra resources
# Requires: pyinstaller

PYTHON := python3
PIP := pip
OS := $(shell uname 2>/dev/null || echo Windows)

DIST := dist

all:
ifeq ($(OS),Linux)
	sudo $(PIP) install -R ./mandatory.txt --break-system-packages
else
	$(PIP) install -R ./mandatory.txt
endif
	client
	server

# Build client executable from decoupage.py with client_key
client:
ifeq ($(OS),Linux)
	$(PYTHON) -m pip install --quiet pyinstaller --break-system-packages
	pyinstaller --onefile \
		--add-data "keys/client_key:keys" \
		--copy-metadata aioftp \
		decoupage.py
else
	$(PYTHON) -m pip install --quiet pyinstaller
	pyinstaller --onefile \
		--add-data "keys\client_key;keys" \
		--copy-metadata aioftp \
		decoupage.py
endif
	@echo "✅ Client built -> $(DIST)/decoupage"

# Build server executable from serveur.py with required files
server:
ifeq ($(OS),Linux)
	$(PYTHON) -m pip install --quiet pyinstaller --break-system-packages
	pyinstaller --onefile \
		--add-data "certificat/server.pem:certificat" \
		--add-data "keys/authorized_keys:keys" \
		--add-data "keys/ssh_host_key:keys" \
		--add-data "keys/ssh_host_key.pub:keys" \
		serveur.py
else
	$(PYTHON) -m pip install --quiet pyinstaller
	pyinstaller --onefile \
		--add-data "certificat\server.pem;certificat" \
		--add-data "keys\authorized_keys;keys" \
		--add-data "keys\ssh_host_key;keys" \
		--add-data "keys\ssh_host_key.pub;keys" \
		serveur.py
endif
	@echo "✅ Server built -> $(DIST)/serveur"

# Execute serveur.py without compiling
exe_server:
ifeq ($(OS),Linux)
	sudo $(PYTHON) serveur.py
else
	$(PYTHON) serveur.py
endif

# Clean build artifacts
clean:
	rm -rf build __pycache__ *.spec $(DIST)

# Rebuild everything
re: clean all
