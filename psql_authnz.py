#!/usr/bin/env python
import os, sys
import time
from psql_authnz.psql_authnz import main

psql_period = os.getenv("PSQL_AUTHNZ_PERIOD", 300)

if __name__ == '__main__':
    while True:
        main()
        time.sleep(psql_period)
