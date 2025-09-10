PYTHON = ~/partage_venv/bin/python3
SERVEUR = serveur.py

all:
	@echo "Serveur prêt à être exécuté"

clean:
	rm -f serveur

re: clean all

install:
	sudo ~/partage_venv/bin/pip install -r mandatory.txt

exe:
	sudo $(PYTHON) $(SERVEUR)
