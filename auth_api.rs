use actix_web::{post, web, HttpResponse, Responder, Result, Error};
use std::{fs, io};
use serde::{Serialize, Deserialize};
use std::path::Path;
use serde_yaml;
use serde_json;
use std::time::{SystemTime, UNIX_EPOCH};
use actix_multipart::form::{
    tempfile::TempFile,
    MultipartForm,
};
use uuid::Uuid;

mod session;

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginBody {
    mail: String,
    password: String
}

#[post("/auth/login")]
pub async fn login(req_body: String) -> impl Responder {
    // todo: ip adresse blockieren nach 5 falschen anfragen ... (-> 1min) 429 too many requests

    let body_str = req_body.to_string();
    let body: LoginBody = serde_json::from_str(&body_str).unwrap();

    let user = session::User::get_by_mail(&body.mail);
    
    if user.is_none() {
        session::hash_someshit();
        return HttpResponse::Unauthorized().body("no valid login")
    }
    
    let user = user.unwrap();
    
    let new_token = user.new_token(&body.password); 
    
    if new_token.is_err() {
        return HttpResponse::Unauthorized().body("no valid login")
    }

    HttpResponse::Ok().body(new_token.unwrap())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutBody {
    token: String,
}

#[post("/auth/revoke")]
pub async fn revoke(req_body: String) -> impl Responder {
    // todo: ip adresse blockieren nach 5 falschen anfragen ... (-> 1min) 429 too many requests

    let body_str = req_body.to_string();
    let body: LogoutBody = serde_json::from_str(&body_str).unwrap();
    let token = session::Token::by_string(&body.token);

    if token.is_none() {
        return HttpResponse::NotFound().body("Token not found / Token is invalid")
    }

    token.unwrap().revoke();

    HttpResponse::Ok().body("terminated session")
}