CYBEX-P CS

# Flask API

#### 0.0 Must be in fsadique home directory

```
# 0. Check and kill if any python scripts are running:
pgrep python
ps -ef | grep python
kill -9 xxxx
pkill python

# 1. Activate Virtual Environment
source ~/venv/bin/activate

# 2. Run Flask API:
cd ~/cybexp-cs/api
nohup python run.py &

# 3. Run Input Stream:
cd ~/cybexp-cs/input
nohup python input.py &

# 4. Run Archive Script
cd ~/cybexp-cs/proc/archive
nohup python archive.py &

# 5. Run Processing Script
cd ~/cybexp-cs/proc/analytics
nohup python analytics.py &

# 6. Run Metric Script
cd ~/cybexp-cs
nohup python metric.py &

# Show all running
ps -ef | grep python
pgrep python
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