use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use anyhow::{Context, Result};
use libloading::Library;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

pub const MAX_IP: usize = 0xFFFF;
pub const RING: u32 = 0x800000;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

type CreateAdapter = unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> *mut c_void;
type OpenAdapter = unsafe extern "system" fn(*const u16) -> *mut c_void;
type CloseAdapter = unsafe extern "system" fn(*mut c_void);
type GetAdapterLuid = unsafe extern "system" fn(*mut c_void, *mut u64);
type GetRunningDriverVersion = unsafe extern "system" fn() -> u32;
type StartSession = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type EndSession = unsafe extern "system" fn(*mut c_void);
type GetReadWaitEvent = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
type ReceivePacket = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type ReleaseReceivePacket = unsafe extern "system" fn(*mut c_void, *mut u8);
type AllocateSendPacket = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(*mut c_void, *mut u8);

pub struct WintunNative {
    _lib: Library,
    create: CreateAdapter,
    open: OpenAdapter,
    close: CloseAdapter,
    luid: GetAdapterLuid,
    version: GetRunningDriverVersion,
    start: StartSession,
    end: EndSession,
    event: GetReadWaitEvent,
    recv: ReceivePacket,
    release: ReleaseReceivePacket,
    alloc: AllocateSendPacket,
    send: SendPacket,
}

impl WintunNative {
    pub fn load(path: &Path) -> Result<Self> {
        let lib = unsafe { Library::new(path) }.with_context(|| format!("load {}", path.display()))?;
        unsafe {
            Ok(Self {
                create: *lib.get(b"WintunCreateAdapter\0")?,
                open: *lib.get(b"WintunOpenAdapter\0")?,
                close: *lib.get(b"WintunCloseAdapter\0")?,
                luid: *lib.get(b"WintunGetAdapterLUID\0")?,
                version: *lib.get(b"WintunGetRunningDriverVersion\0")?,
                start: *lib.get(b"WintunStartSession\0")?,
                end: *lib.get(b"WintunEndSession\0")?,
                event: *lib.get(b"WintunGetReadWaitEvent\0")?,
                recv: *lib.get(b"WintunReceivePacket\0")?,
                release: *lib.get(b"WintunReleaseReceivePacket\0")?,
                alloc: *lib.get(b"WintunAllocateSendPacket\0")?,
                send: *lib.get(b"WintunSendPacket\0")?,
                _lib: lib,
            })
        }
    }
}

pub struct WintunDevice {
    api: WintunNative,
    adapter: *mut c_void,
    session: *mut c_void,
    read_event: *mut c_void,
}

unsafe impl Send for WintunDevice {}
unsafe impl Sync for WintunDevice {}

impl WintunDevice {
    pub const NAME: &'static str = "NanoClash";
    pub const TUNNEL: &'static str = "Wintun";

    pub fn create(api: WintunNative) -> Result<Self> {
        let name = wide(Self::NAME);
        let tunnel = wide(Self::TUNNEL);
        unsafe {
            let leftover = (api.open)(name.as_ptr());
            if !leftover.is_null() {
                (api.close)(leftover);
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            windows_sys::Win32::Foundation::SetLastError(0);
            let mut adapter = ptr::null_mut();
            for _ in 0..5 {
                adapter = (api.create)(name.as_ptr(), tunnel.as_ptr(), ptr::null());
                if !adapter.is_null() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            if adapter.is_null() {
                adapter = (api.open)(name.as_ptr());
                if adapter.is_null() {
                    anyhow::bail!("WintunCreateAdapter/OpenAdapter failed");
                }
            }
            let mut luid = 0u64;
            (api.luid)(adapter, &mut luid);
            let session = (api.start)(adapter, RING);
            if session.is_null() {
                (api.close)(adapter);
                anyhow::bail!("WintunStartSession failed");
            }
            let read_event = (api.event)(session);
            let _ = (api.version)();
            Ok(Self {
                api,
                adapter,
                session,
                read_event,
            })
        }
    }

    pub fn try_receive(&self, buffer: &mut [u8]) -> Result<Option<usize>> {
        if self.session.is_null() {
            return Ok(None);
        }
        unsafe {
            windows_sys::Win32::Foundation::SetLastError(0);
            let mut size = 0u32;
            let ptr = (self.api.recv)(self.session, &mut size);
            if ptr.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                if err == 0 || err == ERROR_NO_MORE_ITEMS {
                    return Ok(Some(0));
                }
                if err == ERROR_HANDLE_EOF {
                    return Ok(None);
                }
                anyhow::bail!("WintunReceivePacket {err}");
            }
            let n = size as usize;
            if n > buffer.len() {
                (self.api.release)(self.session, ptr);
                return Ok(Some(0));
            }
            ptr::copy_nonoverlapping(ptr, buffer.as_mut_ptr(), n);
            (self.api.release)(self.session, ptr);
            Ok(Some(n))
        }
    }

    pub fn wait(&self, timeout_ms: u32) -> bool {
        if self.read_event.is_null() {
            return false;
        }
        unsafe { WaitForSingleObject(self.read_event, timeout_ms) == WAIT_OBJECT_0 }
    }

    pub fn send(&self, packet: &[u8]) {
        if packet.is_empty() || packet.len() > MAX_IP || self.session.is_null() {
            return;
        }
        unsafe {
            windows_sys::Win32::Foundation::SetLastError(0);
            let ptr = (self.api.alloc)(self.session, packet.len() as u32);
            if ptr.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                if err == ERROR_BUFFER_OVERFLOW || err == 0 {
                    return;
                }
                return;
            }
            ptr::copy_nonoverlapping(packet.as_ptr(), ptr, packet.len());
            (self.api.send)(self.session, ptr);
        }
    }

    pub fn end_session(&mut self) {
        if !self.session.is_null() {
            unsafe { (self.api.end)(self.session) };
            self.session = ptr::null_mut();
        }
    }
}

impl Drop for WintunDevice {
    fn drop(&mut self) {
        self.end_session();
        if !self.adapter.is_null() {
            unsafe { (self.api.close)(self.adapter) };
            self.adapter = ptr::null_mut();
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain([0]).collect()
}
