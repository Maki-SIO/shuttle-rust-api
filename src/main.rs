mod model;

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::{from_fn, Next};
use actix_web::web::Json;
use actix_web::{error, get, middleware, post, web, Error, HttpResponse};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use model::User;
use mongodb::{bson::doc, options::IndexOptions, Client, Collection, IndexModel};
use serde::{Deserialize, Serialize};
use shuttle_actix_web::ShuttleActixWeb;
use shuttle_runtime::SecretStore;
use shuttle_runtime::__internals::Context;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

const DB_NAME: &str = "preprod";
const COLL_NAME: &str = "users";

#[utoipa::path(
    post,
    path = "/add_user",
    request_body = User,
    responses(
        (status = 200, description = "User added"),
        (status = 500, description = "Internal Server Error")
    )
)]
#[post("/add_user")]
async fn add_user(client: web::Data<Client>, form: web::Form<User>) -> HttpResponse {
    let collection = client.database(DB_NAME).collection(COLL_NAME);
    let result = collection.insert_one(form.into_inner()).await;
    match result {
        Ok(_) => HttpResponse::Ok().body("user added"),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/get_user/{username}",
    params(
        ("username" = String, Path, description = "The username to lookup")
    ),
    responses(
        (status = 200, description = "User found", body = User),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal Server Error")
    )
)]
#[get("/get_user/{username}")]
async fn get_user(client: web::Data<Client>, username: web::Path<String>) -> HttpResponse {
    let username = username.into_inner();
    let collection: Collection<User> = client.database(DB_NAME).collection(COLL_NAME);
    match collection.find_one(doc! { "username": &username }).await {
        Ok(Some(user)) => HttpResponse::Ok().json(user),
        Ok(None) => {
            HttpResponse::NotFound().body(format!("No user found with username {username}"))
        }
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
struct Claims {
    username: String,
    exp: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
}

fn get_secret_key() -> String {
    "4a77a9735cb3c1392399955f1c8d27b4f68c13832c574bf21ec7cfbc1c0fb663".to_string()
}

fn generate_token(username: &str, exp: usize) -> Result<String, ()> {
    let secret = get_secret_key();

    let claims = Claims {
        username: username.parse().unwrap(),
        exp,
    };

    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
        .unwrap_or_else(|_| "".parse().unwrap()))
}

fn decode_token(token: &str) -> Result<String, String> {
    let secret = get_secret_key();

    let token_message = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    );

    match token_message {
        Ok(token) => Ok(token.claims.username.to_string()),

        Err(err) => Err(format!("Token decoded failed with error {:?}", err)),
    }
}

#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = String),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error")
    )
)]
#[post("/login")]
async fn login(client: web::Data<Client>, form: Json<LoginRequest>) -> HttpResponse {
    let login_request = form.into_inner();
    let collection = client.database(DB_NAME).collection::<User>(COLL_NAME);

    match collection
        .find_one(doc! { "username": &login_request.username })
        .await
    {
        Ok(Some(user)) => match bcrypt::verify(&login_request.password, &user.pwd_hash) {
            Ok(true) => {
                let current_time = chrono::Utc::now().timestamp() as usize;

                let access_exp = current_time + 900; // 15 * 60 : 15 minutes
                let access_token = match generate_token(&user.username, access_exp) {
                    Ok(token) => token,
                    Err(_) => {
                        return HttpResponse::InternalServerError()
                            .body("Error generating access token");
                    }
                };

                let refresh_exp = current_time + 604800; // 7 Day
                let refresh_token = match generate_token(&user.username, refresh_exp) {
                    Ok(token) => token,
                    Err(_) => {
                        return HttpResponse::InternalServerError()
                            .body("Error generating refresh token");
                    }
                };

                let login_response: LoginResponse = LoginResponse {
                    access_token: access_token.to_string(),
                    refresh_token: refresh_token.to_string(),
                };

                HttpResponse::Ok()
                    .content_type("application/json")
                    .json(login_response)
            }
            Ok(false) => HttpResponse::Unauthorized().body("Invalid password"),
            Err(_) => HttpResponse::InternalServerError().body("Error verifying password"),
        },
        Ok(None) => HttpResponse::Unauthorized().body("User not found"),
        Err(_) => HttpResponse::InternalServerError().body("Error finding user"),
    }
}

async fn create_username_index(client: &Client) {
    let options = IndexOptions::builder().unique(true).build();
    let model = IndexModel::builder()
        .keys(doc! { "username": 1 })
        .options(options)
        .build();
    client
        .database(DB_NAME)
        .collection::<User>(COLL_NAME)
        .create_index(model)
        .await
        .expect("creating an index should succeed");
}

#[derive(OpenApi)]
#[openapi(
    paths(add_user, get_user, login),
    components(schemas(User)),
    tags(
        (name = "user", description = "User API")
    )
)]
struct ApiDoc;

async fn middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let bearer = req
        .headers()
        .get("Authorization")
        .ok_or_else(|| error::ErrorUnauthorized("Missing Authorization header"))?
        .to_str()
        .map_err(|_| error::ErrorUnauthorized("Invalid Authorization header"))?;
    let token = &bearer[7..bearer.len()];
    match decode_token(token) {
        Ok(..) => next.call(req).await,
        Err(_) => Err(error::ErrorUnauthorized("Invalid token")),
    }
}

#[shuttle_runtime::main]
async fn main(
    #[shuttle_runtime::Secrets] secrets: SecretStore,
) -> ShuttleActixWeb<impl FnOnce(&mut web::ServiceConfig) + Send + Clone + 'static> {
    let mongodb_uri = secrets.get("MONGODB_URI").context("secret was not found")?;
    let client = Client::with_uri_str(&mongodb_uri)
        .await
        .expect("Erreur de connexion à MongoDB");

    create_username_index(&client).await;

    let client_data = web::Data::new(client);

    let config = move |cfg: &mut web::ServiceConfig| {
        cfg.app_data(client_data.clone()).service(
            web::scope("")
                .service(add_user)
                .service(get_user)
                .service(login)
                .service(
                    SwaggerUi::new("/docs/{_:.*}").url("/api-doc/openapi.json", ApiDoc::openapi()),
                )
                .service(
                    web::resource("/test")
                        .route(web::get().to(HttpResponse::Ok))
                        .wrap(from_fn(middleware)),
                )
                .wrap(middleware::NormalizePath::trim())
                .wrap(middleware::Logger::default()),
        );
    };

    Ok(config.into())
}
