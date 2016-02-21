extern crate libc;

use libc::{c_char, c_int, size_t};

extern
{
	//fn getpwuid_r(uid: uid_t, pwd: *mut libc::passwd, buf: *mut c_char, buflen: size_t, result: *mut *mut libc::passwd) -> c_int
	fn getpwnam_r(name: *const c_char, pwd: *mut libc::passwd, buf: *mut c_char, buflen: size_t, result: *mut *mut libc::passwd) -> c_int;
}

fn write_user_home<W: std::io::Write>(mut writer: W, username: &[u8]) -> Result<usize, std::io::Error>
{
	let mut getpw_string_buf = [0; 4096];
	let mut passwd: libc::passwd = unsafe {std::mem::zeroed()};
	let mut passwd_out: *mut libc::passwd = std::ptr::null_mut();
	let result = if username == &[]
	{
		let uid = unsafe {libc::getuid()};
		unsafe {libc::getpwuid_r(uid, &mut passwd as *mut _,
			getpw_string_buf.as_mut_ptr(), getpw_string_buf.len() as size_t,
			&mut passwd_out as *mut _)}
	}
	else
	{
		let username = match std::ffi::CString::new(username)
		{
			Ok(un) => un,
			Err(_) => return Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
		};
		unsafe {getpwnam_r(username.as_ptr(), &mut passwd as *mut _,
			getpw_string_buf.as_mut_ptr(), getpw_string_buf.len() as size_t,
			&mut passwd_out as *mut _)}
	};
	if result == 0 {
		writer.write(unsafe {std::ffi::CStr::from_ptr(passwd.pw_dir)}.to_bytes())
	}
	else
	{
		Err(std::io::Error::from_raw_os_error(result))
	}
}

/// perform tilde-expansion, replacing an initial ~ or ~username with that username's home directory as determined by getpwnam
pub fn tilde_expand(s: &[u8]) -> Vec<u8>
{
	let mut out = Vec::with_capacity(s.len());
	/* if it starts with ~ and has no other tildes, tilde-expand it */
	match s.first()
	{
		Some(&b'~') if s.iter().filter(|&&c| c==b'~').count() == 1 => {
			let end = s.iter().position(|&c| c==b'/').unwrap_or(s.len());
			let name = &s[1..end];
			let _ = write_user_home(&mut out, name);
			out.extend_from_slice(&s[end..]);
		},
		_ => out.extend_from_slice(s)
	}
	out
}

#[test]
fn test()
{
	println!("{}", String::from_utf8_lossy(&*tilde_expand(b"~/user-test")));
	println!("{}", String::from_utf8_lossy(&*tilde_expand(b"~root/root-test")));
	println!("{}", String::from_utf8_lossy(&*tilde_expand(b"noexpand~/test")));
	println!("{}", String::from_utf8_lossy(&*tilde_expand(b"~~/noexpand-test")));
}
