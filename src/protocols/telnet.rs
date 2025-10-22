// Telnet: summarize IAC negotiations
pub fn decode(data: &[u8]) {
    let mut i = 0usize;
    let mut do_n = 0;
    let mut dont_n = 0;
    let mut will_n = 0;
    let mut wont_n = 0;
    let mut opts: Vec<u8> = Vec::new();
    while i + 2 < data.len() {
        if data[i] == 0xff {
            let cmd = data[i + 1];
            let opt = data[i + 2];
            match cmd {
                0xfd => do_n += 1,
                0xfe => dont_n += 1,
                0xfb => will_n += 1,
                0xfc => wont_n += 1,
                _ => {}
            }
            opts.push(opt);
            i += 3;
        } else {
            i += 1;
        }
        if (do_n + dont_n + will_n + wont_n) > 10 {
            break;
        }
    }
    println!(
        "Telnet bytes={} DO/DOnt={}/{} WILL/WONT={}/{} opts={:?}",
        data.len(),
        do_n,
        dont_n,
        will_n,
        wont_n,
        &opts[..opts.len().min(6)]
    );
}
