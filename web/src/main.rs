use actix_web::{get, web, App, HttpServer, Responder};
use handlebars::{DirectorySourceOptions, Handlebars};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fs, io};

#[actix_web::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let mut handlebars = Handlebars::new();
    handlebars
        .register_templates_directory(
            "./templates",
            DirectorySourceOptions {
                tpl_extension: ".hbs".to_owned(),
                hidden: false,
                temporary: false,
            },
        )
        .unwrap();
    let handlebars_ref = web::Data::new(handlebars);

    HttpServer::new(move || App::new().app_data(handlebars_ref.clone()).service(index))
        .bind(("127.0.0.1", 8081))?
        .run()
        .await
}

#[derive(Serialize, Deserialize, Debug)]
struct Detection {
    path: String,
    size: u64,
    scanned_at: u64,
    time: f64,
    error: Option<String>,
    detected: bool,
    tags: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ScanResults {
    detections: Vec<Detection>,
}

#[get("/")]
async fn index(hb: web::Data<Handlebars<'_>>) -> impl Responder {
    let json_file_path = "report.json";
    let json_data = fs::read_to_string(json_file_path).unwrap();
    let scan_results: ScanResults = serde_json::from_str(&json_data).unwrap();
    let data = json!({ "detections": scan_results.detections });
    let body = hb.render("index", &data).unwrap();

    web::Html::new(body)
}
