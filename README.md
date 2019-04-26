CYBEX-P CS

# Flask API

#### 0.0 Must be in fsadique home directory

```
# 0. Check and kill if any python scripts are running:
ps -ef | grep python
kill -9 xxxx

# 1. Activate Virtual Environment
source ~/.bashrc
workon cybexp

# 2. Run Flask API:
cd ~/cybexp/api
export FLASK_APP=run.py
export FLASK_ENV=development
nohup flask run --host=0.0.0.0 --port=5000 &

# 3. Run Input Stream:
cd ~/cybexp/input
nohup python input.py &

# 4. Run Archive Script
cd ~/cybexp/proc/archive
nohup python archive.py &

# 5. Run Processing Script
cd ~/cybexp/proc/analytics
nohup python analytics.py &

# Show all running
ps -ef | grep python
```

#### API Debug
```
source ~/.bashrc
workon cybexp
cd ~/cybexp/api
export FLASK_APP=run.py
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5000
```
#### Input Debug
```
source ~/.bashrc
workon cybexp
cd ~/cybexp/input
python input.py
```