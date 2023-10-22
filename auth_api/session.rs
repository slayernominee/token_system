use sqlite::State;
use bcrypt::verify;
use uuid::Uuid;
use rand::{distributions::Alphanumeric, Rng};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct Token {
    pub id: i64,
    pub user_id: i64,
    pub token: String,
    pub created: i64,
    pub last_used: i64,
    pub expires: i64,
    pub permissions: i64,
    pub session_name: String,
}

impl Token {
    pub fn by_string(token_string: &str) -> Option<Token> {
        let connection = sqlite::open("auth/auth.db").unwrap();
        let mut statement = connection.prepare("SELECT * FROM tokens WHERE token = ?").unwrap();

        statement.bind((1, token_string)).unwrap();

        while let Ok(State::Row) = statement.next() {
            let token = Token {
                id: statement.read::<i64, _>("id").unwrap(),
                user_id: statement.read::<i64, _>("user_id").unwrap(),
                token: statement.read::<String, _>("token").unwrap(),
                created: statement.read::<i64, _>("created").unwrap(),
                last_used: statement.read::<i64, _>("last_used").unwrap(),
                expires: statement.read::<i64, _>("expires").unwrap(),
                permissions: statement.read::<i64, _>("permissions").unwrap(),
                session_name: statement.read::<String, _>("session_name").unwrap(),
            };
            
            return Some(token)
        }
        
        None
    }

    pub fn revoke(&self) {
        let connection = sqlite::open("auth/auth.db").unwrap();
        let query = format!("DELETE FROM tokens WHERE id = {}", self.id);
        connection.execute(query).unwrap();
    }
}

#[derive(Debug)]
pub struct User {
    pub id: i64,
    pub mail: String,
    pub password: String,
    pub totp: String,
    pub created: i64,
    pub last_login: i64,
    pub firstname: String,
    pub name: String,
    pub admin: bool,
}

#[derive(Debug)]
pub enum TokenGenError {
    WrongPassword,
}

impl User {
    pub fn get_by_mail(mail: &str) -> Option<User> {
        let connection = sqlite::open("auth/auth.db").unwrap();
        let mut statement = connection.prepare("SELECT * FROM users WHERE mail = ?").unwrap();
        
        statement.bind((1, mail)).unwrap();
        
        while let Ok(State::Row) = statement.next() {
            let user = User {
                id: statement.read::<i64, _>("id").unwrap(),
                mail: statement.read::<String, _>("mail").unwrap(),
                password: statement.read::<String, _>("password").unwrap(),
                totp: statement.read::<String, _>("totp").unwrap(),
                created: statement.read::<i64, _>("created").unwrap(),
                last_login: statement.read::<i64, _>("last_login").unwrap(),
                firstname: statement.read::<String, _>("firstname").unwrap(),
                name: statement.read::<String, _>("name").unwrap(),
                admin: statement.read::<i64, _>("admin").unwrap() != 0,
            };
            
            return Some(user)
        }
        
        None
    }
    
    pub fn new_token(&self, password: &str) -> Result<String, TokenGenError> {
        let valid = verify(password, &self.password).unwrap();

        if valid {
            let uuid = Uuid::new_v4();
            
            let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();
            
            let new_token = self.id.to_string() + "." + &uuid.to_string() + "." + &s;
            
            let timestamp = get_timestamp();
            let expires = timestamp + 60 * 60 * 24 * 14; // 14 days

            let connection = sqlite::open("auth/auth.db").unwrap();
            let query = format!("INSERT INTO tokens(user_id, token, created, last_used, expires, permissions, session_name) VALUES ({}, '{}', {}, {}, {}, {}, '{}')", self.id, new_token, timestamp, 0, expires, 1, "");
            connection.execute(query).unwrap();
            
            Ok(new_token)
        } else {
            Err(TokenGenError::WrongPassword)
        }
    }
}

pub fn hash_someshit() {
    verify("some_random_hashing_to_take_time", "$2b$12$NkpoOMHTACkO89wTuJqpJ.DTiV08.firOceUyXigz6W2CFEodNJgi").unwrap();
}

pub fn get_timestamp() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");
    
    since_the_epoch.as_secs()
}