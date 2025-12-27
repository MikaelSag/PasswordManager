
## Requirements
- Python 3.x
- Flask library `pip install flask`
- Flask DB Library `pip install flask_mysqldb`
- Dotenv `pip install dotenv`
- Argon `pip install argon2-cffi`
- Cryptography `pip install cryptography`
- Docker Desktop
- mySQL version 8
- .env file with the following fields: `MYSQL_ROOT_PASSWORD`,`MYSQL_DATABASE`,`MYSQL_USER`,`MYSQL_PASSWORD`,`MYSQL_PORT`,`FLASK_SECRET_KEY`

## How to Run
1. Install dependencies ```pip install -r requirements.txt```
2. Open Terminal/Powershell
3. Change working directory to installation folder (```cd $env:HOMEPATH\Documents\GitHub\PassUTD```)
4. If running for the first time: ```docker compose up --build -d```
5. If running anytime after: ```docker compose up -d```
6. Start mysql: ```mysql -h 127.0.0.1 -P 3307 -u root -p --execute="source Database Script.sql"```
7. Type in your password for `MYSQL_ROOT_PASSWORD`
8. Run app.py `python3 app.py`
9. Open local host in a web browser `http://localhost:5000/`

