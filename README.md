# Anonymous Chat 💬🚀

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
Make sure to install the following dependencies:

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

4. **Connecting to MySQL**:
    Use the following command to interact with MySQL:
    ```
    mysql -u root -p
    ```
    And enter your password

5. **Creating a New Database & User**:
   Create a new database:
   ```sql
   CREATE DATABASE anonymouschatdb;
   ```
   By default, MySQL will have a 'root' user. But we will create a new user:
    ```sql
    CREATE USER 'username'@'localhost' IDENTIFIED BY 'password';
    GRANT ALL PRIVILEGES ON anonymouschatdb.* TO 'username'@'localhost';
    FLUSH PRIVILEGES;
    exit;
    ```

6. **Setting up the MySQL URI as an Environmental Variable**:

	For security reasons, it's recommended to store sensitive data like database URIs as environmental variables rather than hardcoding them into your application.
	
	1. **Windows**:
	    ```
	    setx DATABASE_URI "mysql+pymysql://[USERNAME]:[PASSWORD]@[HOST]/[DATABASE_NAME]"
	    ```
	
	2. **MacOS and Linux**:
	    ```
	    echo 'export DATABASE_URI="mysql+pymysql://god:Amine1010<3!@localhost/anonymouschatdb"' >> ~/.bash_profile
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


## Setting up Nginx and Gunicorn for Flask 🚀

Flask applications can be served using a combination of Nginx and Gunicorn. Nginx acts as a reverse proxy, directing web traffic to backend applications served by Gunicorn.

### Prerequisites 🔍
- Basic knowledge of the command line.

### Linux Setup 🐧

#### Installing Nginx 💻
1. Update your package lists:
    ```bash
    sudo apt update
    ```
2. Install Nginx:
    ```bash
    sudo apt install nginx
    ```

#### Installing Gunicorn 🦄
1. Ensure you have `pip` installed:
    ```bash
    sudo apt install python3-pip
    ```
2. Install Gunicorn:
    ```bash
    pip3 install gunicorn
    ```

#### Configuring Nginx for Flask 🛠️
1. Create a new Nginx configuration for your Flask app:
    ```bash
    sudo nano /etc/nginx/sites-available/myflaskapp
    ```

2. Add the following to the configuration file, adjusting the server_name and proxy_pass as needed:
    ```nginx
    server {
        listen 80;
        server_name yourdomain.com www.yourdomain.com;

        location / {
            proxy_pass http://127.0.0.1:5000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
    ```

3. Create a symbolic link to the `sites-enabled` directory:
    ```bash
    sudo ln -s /etc/nginx/sites-available/myflaskapp /etc/nginx/sites-enabled
    ```

4. Test Nginx configuration:
    ```bash
    sudo nginx -t
    ```

5. Reload Nginx to apply changes:
    ```bash
    sudo systemctl reload nginx
    ```

#### Running the Flask App with Gunicorn 🚀
1. Navigate to your Flask application directory.
2. Run your app with Gunicorn:
    ```bash
    gunicorn app:app -b 127.0.0.1:5000
    ```

### Windows Setup (using WSL) 🪟

#### Installing Windows Subsystem for Linux (WSL) 🖥️
1. Open PowerShell as Administrator.
2. Run the following command to enable the WSL feature:
    ```bash
    wsl --install
    ```

3. Reboot your computer if prompted.
4. Install your preferred Linux distribution from the Microsoft Store (e.g., Ubuntu).

#### Follow Linux Setup Inside WSL ⬆️
Once you have WSL and a Linux distribution installed, you can follow the [Linux Setup](#linux-setup) section above to set up Nginx and Gunicorn inside your WSL environment.

---

That's it! 🎉 Your Flask application should now be accessible via your domain, served by Gunicorn, and proxied by Nginx.

## Website live 🎥

https://github.com/obaskly/AnonymousChat/assets/11092871/908a8466-1bc8-4996-abe5-0453a4aaa86e



## Contribution 🤝
Feel free to fork, improve, make pull requests or fill issues. I'll appreciate any help and feedback!

## License 📜
This project is open-source and available under the MIT License.

---
**Happy Coding!** 💻🐍
