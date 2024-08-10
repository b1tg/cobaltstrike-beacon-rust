use std::{
    io::Read,
    process::{Command, Stdio},
};

use reqwest::header::{COOKIE, USER_AGENT};

use anyhow::{bail, Result};
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
    // throw error when app not found
    let output = command.output()?;
    let stdout = String::from_utf8(output.stdout);
    Ok(stdout?)
}
pub fn os_system_anyway(cmd_line: &str) -> String {
    let res = os_system(cmd_line);
    if res.is_err() {
        return format!("{:?}", res.err().unwrap());
    }
    return res.unwrap();
}

#[test]
fn test_os_system() {
    assert_eq!("program not found", os_system_anyway(&"whoami1"));
}

pub fn win_os_system(cmd_line: &str) -> Result<String> {
    let cmd_line_split: Vec<&str> = if cfg!(windows) {
        cmd_line.split(',').collect()
    } else {
        cmd_line.split_ascii_whitespace().collect()
    };

    if cmd_line_split.is_empty() {
        return Ok("".into());
    }

    let app = cmd_line_split[0];
    let mut command = if cfg!(windows) {
        Command::new("cmd")
    } else {
        Command::new(app)
    };

    if cfg!(windows) {
        command.arg("/C").arg(app.replace("/", "\\"));
    } else {
        for arg in &cmd_line_split[1..] {
            command.arg(arg);
        }
    }

    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let output_str = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        bail!(
            "command failed with error code {}",
            output.status.code().unwrap_or(-1)
        );
    }
    let result = if cfg!(windows) {
        output_str.trim_end_matches("\r\n").to_owned()
    } else {
        output_str.to_string()
    };

    Ok(result)
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
