use sqlite::State;
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

pub fn get_timestamp() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");
    
    since_the_epoch.as_secs()
}

pub fn check_token(token: &str) -> bool {
    let token = token.split(" ").collect::<Vec<&str>>()[1];

    let connection = sqlite::open("auth/auth.db").unwrap();
    let mut statement = connection.prepare("SELECT * FROM tokens WHERE token = ? AND expires > ?").unwrap();
    
    statement.bind((1, token)).unwrap();
    statement.bind((2, get_timestamp() as i64)).unwrap();
    
    while let Ok(State::Row) = statement.next() {
        return true;
        
    }
    
    false
}