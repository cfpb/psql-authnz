req:
	pip install -r requirements.txt

sync:
	python psql_authnz.py

init: req
	psql -c "CREATE ROLE users LOGIN;"
	psql -c "CREATE ROLE admins LOGIN;"