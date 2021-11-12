## Adding proxy support to PyGithub ##

1. The 3 files in this dir, enable adding proxy support to github module.
   
2. The 3 files `MainClass.py`, `Requester.py` and `Requester.pyi` must be copied into corresponding Python venv,
site-packages path, example `venv/lib/python3.8/site-packages/github`.
   
3. While instantiating Github, pass ` proxies = {'http': 'http://proxymdomain.com:80', 'https':'https://proxy.domain.com:80}` to set the proxy.