# About
This project is a proof of concept to demonstrate a website that is encrypted independent of TLS.

# Running In Development
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
FLASK_ENV=development REDISCLOUD_URL=redis://127.0.0.1:6379 flask run --port 5001
```

# Production
Available [here](https://cryptic-fjord-38672.herokuapp.com/).