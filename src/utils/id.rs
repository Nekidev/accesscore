use chrono::Utc;
use nanoid::nanoid;

pub fn gen_id(size: Option<usize>) -> String {
    let size = size.unwrap_or(16);

    let timestamp = Utc::now().timestamp_millis();
    let random_id = nanoid!(size);

    format!("{}-{}", timestamp, random_id)
}
