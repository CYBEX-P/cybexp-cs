
# Filter requirement
New filters MUST have a function named as the contents of variable `function_name` in analytics.py:analytics(), otherwise they will not be inlclused in the filters module and will not run in the analytisc.py.   

```python
function_name = "filt_main"

```
   
# Enable a filter
Create relative symlink   
```bash
ln -rs <module1.py> ../enabled/
```
