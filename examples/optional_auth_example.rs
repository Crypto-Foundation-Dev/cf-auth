use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use cf_auth::{
    ApiResponse,
    middleware::{OptionalUser, optional_firebase_auth_middleware},
};

/// Public endpoint that behaves differently for logged-in users
async fn public_content(user: OptionalUser) -> impl Responder {
    match &user.0 {
        Some(u) => {
            // User is authenticated
            HttpResponse::Ok().json(ApiResponse::success(
                format!("Personalized content for {}", u.uid),
                "Successfully retrieved content",
            ))
        }
        None => {
            // User is anonymous
            HttpResponse::Ok().json(ApiResponse::success(
                "Public content for guest".to_string(),
                "Successfully retrieved content",
            ))
        }
    }
}

/// Protected endpoint (for comparison)
#[allow(dead_code)]
async fn protected_content() -> impl Responder {
    HttpResponse::Ok().json(ApiResponse::success(
        "This is strictly protected content.".to_string(),
        "Access granted",
    ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    tracing::info!("Starting server at http://127.0.0.1:8080");

    HttpServer::new(|| {
        App::new()
            // Apply optional auth middleware globally or to specific scope
            .wrap(actix_web::middleware::from_fn(
                optional_firebase_auth_middleware,
            ))
            .route("/public", web::get().to(public_content))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
