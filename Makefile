PYTHON = ~/partage_venv/bin/python3
SERVEUR = serveur.py

all:
	@echo "Serveur prêt à être exécuté"

clean:
	rm -f serveur

re: clean all

install:
	pip install -r mandatory.txt

exe:
	sudo systemctl stop tor
	sudo -u debian-tor tor &
	sudo $(PYTHON) $(SERVEUR)
