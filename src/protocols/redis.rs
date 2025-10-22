// Minimal Redis (RESP) decoder
// RESP prefixes: + - : $ * (RESP2) and RESP3 adds _ , # , ~ , = , > , %

fn resp_type_name(b: u8) -> &'static str {
    match b as char {
        '+' => "simple",
        '-' => "error",
        ':' => "integer",
        '$' => "bulk",
        '*' => "array",
        '_' => "null",
        '#' => "bool",
        '~' => "set",
        '=' => "verbatim",
        '>' => "push",
        '%' => "map",
        _ => "unknown",
    }
}

pub fn decode(data: &[u8]) {
    if data.is_empty() {
        println!("Redis (empty)");
        return;
    }
    let kind = resp_type_name(data[0]);
    // print first line up to CRLF for context
    let mut end = data.len();
    for i in 0..data.len().saturating_sub(1) {
        if data[i] == b'\r' && data[i + 1] == b'\n' {
            end = i;
            break;
        }
        if data[i] == b'\n' {
            end = i;
            break;
        }
    }
    let preview = std::str::from_utf8(&data.get(0..end).unwrap_or(&[])).unwrap_or("");
    println!("Redis {}: {}", kind, preview);
}
