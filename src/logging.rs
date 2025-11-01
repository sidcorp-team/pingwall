use log::{LevelFilter, Record};
use log4rs::{
    append::console::ConsoleAppender,
    append::file::FileAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
    filter::Filter,
};

// Custom filter to exclude ERROR level messages
#[derive(Debug)]
struct ExcludeErrorFilter;

impl Filter for ExcludeErrorFilter {
    fn filter(&self, record: &Record) -> log4rs::filter::Response {
        if record.level() == log::Level::Error {
            log4rs::filter::Response::Reject
        } else {
            log4rs::filter::Response::Accept
        }
    }
}

pub fn init_logger() -> Result<(), Box<dyn std::error::Error>> {
    // Define the pattern for log messages
    let pattern = "{d(%Y-%m-%dT%H:%M:%S%.6f%Z)} - {l} - {m}{n}";

    // Console appender for all logs
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();

    // File appender for all logs except ERROR
    let all_logs = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build("logs/application.log")?;

    // File appender specifically for errors
    let error_logs = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build("logs/error.log")?;

    // Create a config with all appenders
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(
            Appender::builder()
                .filter(Box::new(ExcludeErrorFilter))
                .build("all_logs", Box::new(all_logs))
        )
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(LevelFilter::Error)))
                .build("error_logs", Box::new(error_logs))
        )
        .build(
            Root::builder()
                .appender("stdout")
                .appender("all_logs")
                .appender("error_logs")
                .build(LevelFilter::Info)
        )?;

    // Initialize the log4rs logger with our config
    log4rs::init_config(config)?;
    Ok(())
}