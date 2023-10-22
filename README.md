# Setup

1. Clone this git repo in your actix project
2. Copy the content in the `src` folder by running `cp -r token_system/* src/`
3. Modify the `main.rs`
by adding
```rs
// import the tokencheck in the main.rs 
mod tokencheck;
mod auth_api;

// add the auth api by 
.service(
    web::scope("/auth_api/v1")
    .service(auth_api::login)
    .service(auth_api::revoke)
)

// wrap your routes with the tokencheck e.g.
.service(
web::scope("/api/v1")
.wrap(tokencheck::TokenCheck)
)

// auth db creation 
// TODO!!!: use a random generated password and username 
    if ! std::path::Path::new("auth").exists() {
        println!("Creating directory: auth");
        fs::create_dir_all("auth").unwrap();

        let connection = sqlite::open("auth/auth.db").unwrap();
        let query = "
            CREATE TABLE users (id INTEGER PRIMARY KEY, mail TEXT NOT NULL, password TEXT NOT NULL, totp TEXT NOT NULL, created INTEGER, last_login INTEGER, firstname TEXT, name TEXT, admin INTEGER);
            INSERT INTO users VALUES (1, 'root@root.de', '$2b$12$NkpoOMHTACkO89wTuJqpJ.DTiV08.firOceUyXigz6W2CFEodNJgi', '', 0, 0, 'root', 'root', 1);

            CREATE TABLE tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token TEXT NOT NULL, created INTEGER, last_used INTEGER, expires INTEGER, permissions INTEGER NOT NULL, session_name TEXT, FOREIGN KEY(user_id) REFERENCES users(id));
        ";

        connection.execute(query).unwrap();

        // bcrypt 12 rounds

        println!("you can login in the via the username: root@root.de and the password: lol_zero123. Directly login and change it!");
    }
```
