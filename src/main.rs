mod model;

use actix_web::web::Json;
use actix_web::{get, post, web, HttpResponse};
use jsonwebtoken::{encode, EncodingKey, Header};
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
    token: String,
}

fn get_secret_key() -> String {
    "4a77a9735cb3c1392399955f1c8d27b4f68c13832c574bf21ec7cfbc1c0fb663".to_string()
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
                let claims = Claims {
                    username: user.username.clone(),
                    exp: 10000000000,
                };

                let secret = get_secret_key();
                match encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(secret.as_ref()),
                ) {
                    Ok(token) => HttpResponse::Ok()
                        .content_type("application/json")
                        .json(LoginResponse { token }),
                    Err(_) => HttpResponse::InternalServerError().body("Error generating JWT"),
                }
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
        cfg.app_data(client_data.clone())
            .service(add_user)
            .service(get_user)
            .service(login)
            .service(
                SwaggerUi::new("/docs/{_:.*}").url("/api-doc/openapi.json", ApiDoc::openapi()),
            );
    };

    Ok(config.into())
}
