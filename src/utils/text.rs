/// Trims a text. If the string length exceeds `max_length`, it'll be cut to be
/// `max_length` characters long and prepended an ellipsis (`...`).
pub fn trim(input: &str, max_length: usize) -> String {
    if input.len() > max_length {
        format!("{}...", &input[..max_length])
    } else {
        input.to_string()
    }
}
