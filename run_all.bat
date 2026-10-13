@echo off
REM Full pipeline. Run from the repository folder with the venv active.
python scripts\detect.py || exit /b 1
python scripts\campaigns.py || exit /b 1
python scripts\pairwise.py || exit /b 1
python scripts\engine.py --prior population --scorer surprise --tag A_static_population_surprise || exit /b 1
python scripts\engine.py --prior peer --scorer surprise --tag B_static_peer_surprise || exit /b 1
python scripts\engine.py --prior peer --scorer density --tag C_static_peer_density || exit /b 1
python scripts\engine.py --prior peer --scorer surprise --regime oracle --tag D_oracle_peer_surprise || exit /b 1
python scripts\engine.py --prior peer --scorer density --confirm-watch src --tag F_static_peer_density_watchsrc || exit /b 1
python scripts\compare.py
