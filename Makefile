
virtualenv -p python 2.7 env
source env/bin/active
flake8 --ignore=W191 ddosdetect/
isort DDOSDetector/ddosdetect/*
python ddetect.py -i input.txt -o out.txt -n 87
deactivate
