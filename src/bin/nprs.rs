#[tokio::main]
async fn main() {
    std::process::exit(nprobe_rs::run_cli().await);
}
