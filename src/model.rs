use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct User {
    pub name: String,
    #[serde(rename = "firstName")]
    pub first_name: String,
    pub username: String,
    #[serde(rename = "pwdHash")]
    pub pwd_hash: String,
    #[serde(rename = "hireDate")]
    pub hire_date: String,
    pub department: String,
}