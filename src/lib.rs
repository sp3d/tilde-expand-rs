extern crate libc;

use libc::{c_char, c_int, size_t};

extern "C" {
    //fn getpwuid_r(uid: uid_t, pwd: *mut libc::passwd, buf: *mut c_char, buflen: size_t, result: *mut *mut libc::passwd) -> c_int
    fn getpwnam_r(
        name: *const c_char,
        pwd: *mut libc::passwd,
        buf: *mut c_char,
        buflen: size_t,
        result: *mut *mut libc::passwd,
    ) -> c_int;
}

fn write_user_home<W: std::io::Write>(
    mut writer: W,
    username: &[u8],
) -> Result<usize, std::io::Error> {
    let mut getpw_string_buf = [0; 4096];
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut passwd_out: *mut libc::passwd = std::ptr::null_mut();
    let result = if username.is_empty() {
        let uid = unsafe { libc::getuid() };
        unsafe {
            libc::getpwuid_r(
                uid,
                &mut passwd as *mut _,
                getpw_string_buf.as_mut_ptr(),
                getpw_string_buf.len() as size_t,
                &mut passwd_out as *mut _,
            )
        }
    } else {
        let username = match std::ffi::CString::new(username) {
            Ok(un) => un,
            Err(_) => return Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
        };
        unsafe {
            getpwnam_r(
                username.as_ptr(),
                &mut passwd as *mut _,
                getpw_string_buf.as_mut_ptr(),
                getpw_string_buf.len() as size_t,
                &mut passwd_out as *mut _,
            )
        }
    };
    if result == 0 {
        writer.write(unsafe { std::ffi::CStr::from_ptr(passwd.pw_dir) }.to_bytes())
    } else {
        Err(std::io::Error::from_raw_os_error(result))
    }
}

/// perform tilde-expansion, replacing an initial ~ or ~username with that username's home directory as determined by getpwnam
pub fn tilde_expand(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    /* if it starts with ~ and has no other tildes before /, tilde-expand it */
    let maybe_name = if s.starts_with(b"~") {
        let end = s.iter().position(|&c| b'/' == c).unwrap_or_else(|| s.len());
        let name = &s[1..end];
        let rest = &s[end..];
        if name.contains(&b'~') {
            None
        } else {
            Some((name, rest))
        }
    } else {
        None
    };
    if let Some((name, rest)) = maybe_name {
        let _ = write_user_home(&mut out, name);
        out.extend_from_slice(rest);
    } else {
        out.extend_from_slice(s)
    }
    out
}

#[test]
fn test_output_equals_bash() {
    use std::process::Command;
    fn bash(path: &[u8]) -> Vec<u8> {
        Command::new("sh")
            .arg("-c")
            .arg(format!("echo -n {}", String::from_utf8_lossy(path)))
            .output()
            .expect("failed to execute process")
            .stdout
    }
    fn check_output_equals(path: &[u8]) {
        let internal = tilde_expand(path);
        let reference = bash(path);
        assert_eq!(
            internal,
            reference,
            "'{}' differs from expected '{}'",
            String::from_utf8_lossy(&internal),
            String::from_utf8_lossy(&reference)
        );
    }
    check_output_equals(b"~/user-test");
    check_output_equals(b"~root/root-test");
    check_output_equals(b"~root/root~test");
    check_output_equals(b"noexpand~/test");
    check_output_equals(b"~~/noexpand-test");
}
