// Token Check is a middleware ...

use std::{future::{ready, Ready}, fs};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use serde::{Serialize, Deserialize};
use serde_yaml;
use futures_util::future::LocalBoxFuture;

mod token;

#[derive(Debug, Serialize, Deserialize)]
pub struct AvailableTokens {
    bearer: Vec<String>,
}

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct TokenCheck;

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for TokenCheck
where
S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
S::Future: 'static,
B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = TokenCheckMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    
    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(TokenCheckMiddleware { service }))
    }
}

pub struct TokenCheckMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for TokenCheckMiddleware<S>
where
S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
S::Future: 'static,
B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;
    
    forward_ready!(service);
    
    fn call(&self, req: ServiceRequest) -> Self::Future {
        //println!("req path: {}", req.path());

        if ! (req.path() == "/auth_api/v1/login") {
            let headers = req.headers();
            //println!("headers: {:?}", headers);
            // get authorization header
            let token = headers.get("Authorization");
            if token.is_none() {
                // return error authorization header not found
                let error = actix_web::error::ErrorUnauthorized("Authorization header not found").into();
                return Box::pin(async move { Err(error) });
            }
            
            let token = token.unwrap().to_str().unwrap();
            
            let token_valid = token::check_token(token);
            
            if ! token_valid {
                let error = actix_web::error::ErrorForbidden("No valid Token").into();
                return Box::pin(async move { Err(error) })
            }
        }
        
        // The Service is called -> request will be processesed
        let fut = self.service.call(req);
        
        Box::pin(async move {
            let res = fut.await?;
            // res is the server response and will be processed 
            Ok(res)
        })
    }
}
