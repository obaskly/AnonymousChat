# Anonymous Chat 🚀

A modern chat application built with Flask.

## Features 🌟
1. **User Authentication & Sessions**: Uses Flask-Login and Flask-Session for seamless user authentication and session management.
2. **Database Integration**: Integrated with SQLAlchemy for efficient database operations.
3. **Form Handling**: Utilizes Flask-WTF for form creation, handling, and validation.
4. **Rate Limiting**: Implements Flask-Limiter for limiting request rates and ensuring application reliability.
5. **Password Security**: Uses Bcrypt for password hashing, ensuring user data security.
6. **End-to-End Encryption**: Employs the cryptography library for encrypting and decrypting messages, ensuring privacy.
7. **Task Scheduling**: Uses APScheduler for periodic task execution.
8. **Redis Integration**: Implements Redis as a session store for better performance and scalability.

## Setup & Usage 💼

### Dependencies 📦
Make sure to install the following dependencies using pip:

```
pip install flask flask-sqlalchemy flask-login flask-wtf flask-limiter flask-bcrypt flask-session cryptography apscheduler redis email-validator WTForms pymysql
```

### Database Setup (MySQL) 🗃️

1. **Installing MySQL**:
    - **Windows**: Download the [MySQL Installer](https://dev.mysql.com/downloads/installer/) and follow the prompts.
    - **MacOS**: Use Homebrew: `brew install mysql`
    - **Linux (Ubuntu)**:
        ```
        sudo apt update
        sudo apt install mysql-server
        ```

2. **Starting MySQL**:
    - **Windows**: Use the MySQL Notifier icon or services panel.
    - **MacOS**: `mysql.server start`
    - **Linux**: `sudo systemctl start mysql`

3. **Securing MySQL**:
    After installing, it's crucial to secure your MySQL installation:
    ```
    sudo mysql_secure_installation
    ```

4. **Creating a New User**:
    By default, MySQL will have a 'root' user. To create a new user:
    ```sql
    CREATE USER 'username'@'localhost' IDENTIFIED BY 'password';
    GRANT ALL PRIVILEGES ON *.* TO 'username'@'localhost' WITH GRANT OPTION;
	FLUSH PRIVILEGES;
    ```

5. **Connecting to MySQL**:
    Use the following command to interact with MySQL:
    ```
    mysql -u username -p
    ```

6. **Setting up the MySQL URI as an Environmental Variable**:

	For security reasons, it's recommended to store sensitive data like database URIs as environmental variables rather than hardcoding them into your application.
	
	1. **Windows**:
	    ```
	    setx MYSQL_URI "mysql+pymysql://[USERNAME]:[PASSWORD]@[HOST]/[DATABASE_NAME]"
	    ```
	
	2. **MacOS and Linux**:
	    ```
	    echo 'export MYSQL_URI="mysql+pymysql://[USERNAME]:[PASSWORD]@[HOST]/[DATABASE_NAME]"' >> ~/.bash_profile
	    source ~/.bash_profile
	    ```
	
	Replace `[USERNAME]`, `[PASSWORD]`, `[HOST]`, and `[DATABASE_NAME]` with your actual database credentials.

### Redis Setup 🎈
1. **Download and Install Redis**:
    - **Windows**: 
        1. Install using pip: `pip install redis`
        2. Download and install from [Redis Windows Release](https://github.com/microsoftarchive/redis/releases/download/win-3.0.504/Redis-x64-3.0.504.msi)
    - **MacOS**: Use Homebrew: `brew install redis`
    - **Linux (Ubuntu)**:
        ```
        sudo apt update
        sudo apt install redis-server
        ```

2. **Start the Redis Server**:
    - MacOS, Linux, or WSL on Windows: Use the `redis-server` command.

3. **Verify Redis is Running**:
    - Use the `redis-cli` tool and type: `redis-cli ping`. If the server is running, it should respond with `PONG`.

4. **Secure Your Redis Server**:
    - Go to the Redis configuration file. Sometimes you might have two configuration files, edit both.
        - Uncomment the line: `bind 127.0.0.1`
        - Restart the Redis server.
    - **Set a Password and Disable Dangerous Commands**:
        - In the configuration file(s), add:

        ```
        requirepass "YOUR_STRONG_PASSWORD_HERE"
        rename-command CONFIG ""
        rename-command FLUSHALL ""
        rename-command DEL ""
        rename-command FLUSHDB ""
        ```

        - Save the password as an environmental variable:
            - Windows: `setx REDIS_PASSWORD "YOUR_PASSWORD_HERE"`
            - Linux: `export REDIS_PASSWORD="YOUR_PASSWORD_HERE"`
        - Restart your Redis server.

## Contribution 🤝
Feel free to fork, improve, make pull requests or fill issues. I'll appreciate any help and feedback!

## License 📜
This project is open-source and available under the MIT License.

---
**Happy Coding!** 🎉
