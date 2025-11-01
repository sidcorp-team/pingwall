use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(long, default_value_t = 60)]
    pub max_req_per_window: isize,

    #[arg(long, default_value_t = 300)]
    pub block_duration_secs: u64,

    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    #[arg(long, default_value = "127.0.0.1:9992")]
    pub upstream_addr: String,

    #[arg(long, default_value = "https://example.com/api/v1/block")]
    pub block_url: String,

    #[arg(long, default_value = "your-api-key")]
    pub api_key: String,

    #[arg(long, default_value_t = false)]
    pub use_cloudflare: bool,

}
