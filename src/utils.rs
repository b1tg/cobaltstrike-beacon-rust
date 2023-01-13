use std::{io::Read, process::Command};

use reqwest::header::{COOKIE, USER_AGENT};

use anyhow::Result;
pub fn os_system(cmd_line: &str) -> Result<String> {
    let cmd_line_split: Vec<&str> = cmd_line.split_ascii_whitespace().collect();
    if cmd_line_split.len() < 1 {
        return Ok("".into());
    }
    let app = cmd_line_split[0];
    let mut command = Command::new(app);
    for arg in &cmd_line_split[1..] {
        command.arg(arg);
    }
    Ok(String::from_utf8(command.output().unwrap().stdout).unwrap())
}

pub fn read_data(r: &mut impl Read) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).ok()?;
    let l = u32::from_be_bytes(len_buf.try_into().unwrap()) as usize;
    let mut buf = vec![0; l];
    r.read_exact(&mut buf).ok()?;
    Some(buf)
}

pub struct Strike();
impl Strike {
    pub fn http_get(
        url: &str,
        cookie: &str,
        user_agent: &str,
    ) -> Result<reqwest::blocking::Response, reqwest::Error> {
        let client = reqwest::blocking::Client::new();
        client
            .get(url)
            .header(COOKIE, cookie)
            .header(USER_AGENT, user_agent)
            .send()
    }

    pub fn http_post(
        url: &str,
        cookie: &str,
        user_agent: &str,
        data: Vec<u8>,
    ) -> Result<reqwest::blocking::Response, reqwest::Error> {
        let client = reqwest::blocking::Client::new();
        client
            .post(url)
            .header(COOKIE, cookie)
            .header(USER_AGENT, user_agent)
            .body(data)
            .send()
    }
}
