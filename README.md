# BirthTrack

## Start the Node server

Run `node server.js` and open `http://localhost:3000`. On first use, create the administrator account you choose. Applicants can create their own accounts from the login screen. The server stores salted password hashes in the local `users.json` file; application records are stored in `data.json`. These runtime files are ignored by Git.

## GitHub Pages

The static GitHub Pages fallback stores account and application data in the current browser only. It is a prototype, not secure shared authentication or a production database. Use the `xampp/` folder for the PHP/MySQL version and XAMPP deployment.