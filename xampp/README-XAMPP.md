# BirthTrack on XAMPP

## Install

1. Extract the package contents into `C:\xampp\htdocs\BirthTrack` (create the folder if needed).
2. Start **Apache** and **MySQL** in the XAMPP Control Panel.
3. Open `http://localhost/phpmyadmin`, select **Import**, and import `database.sql`.
4. Open `http://localhost/BirthTrack/`.
5. On first use, create the administrator account. Members can create applicant accounts from the login screen.

The default database settings in `config.php` match a standard local XAMPP install (`127.0.0.1`, database `birthtrack`, user `root`, blank password). If your MySQL root account has a password, update the password setting or define `BIRTHTRACK_DB_PASSWORD` in the PHP environment before opening the app.

## Data and accounts

Accounts and applications are stored in MySQL. Passwords are stored as PHP password hashes. Applicant accounts can be self-registered; administrators and clerks are created by an administrator. The initial administrator is created through the first-use setup screen.

The previous browser-only prototype's localStorage data is not automatically copied into this database. Keep the old package if you need that data.

Use this XAMPP setup locally for development. Before exposing the app to a network, configure a dedicated database user with a strong password, HTTPS, backups, and appropriate operational security.
