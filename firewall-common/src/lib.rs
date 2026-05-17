#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub enum IpAddress {
    Ipv4(u32),
    Ipv6([u8; 16]),
}