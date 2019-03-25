CYBEX-P CS

Flask API

0.0 Must be in fsadique home directory

0.1 Activate Virtual Environment

source ~/.bashrc
workon cybexp

0.2 Check and kill if any python scripts are running:

ps -ef | grep python
kill -9 xxxx

1. Run Flask API:

cd ~/cybexp/api
export FLASK_APP=run.py
export FLAKS_ENV=development
nohup flask run --host=0.0.0.0 --port=5000 &

2. Run Input Stream:

cd ~/cybexp/input
nohup python run.py &

3. Run Archive Script
cd ~/cybexp/proc/archive
nohup python archive.py &
