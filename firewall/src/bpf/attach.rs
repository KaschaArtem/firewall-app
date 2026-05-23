use anyhow::Context as _;
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, tc};

pub fn attach_programs(ebpf: &mut aya::Ebpf, interface: &str) -> anyhow::Result<()> {
    let xdp: &mut Xdp = ebpf
        .program_mut("ingress_xdp")
        .context("failed to find ingress_xdp program")?
        .try_into()
        .context("failed to cast ingress_xdp to Xdp")?;
    xdp.load()?;
    xdp.attach(interface, XdpFlags::default())
        .context("failed to attach ingress XDP program")?;

    let _ = tc::qdisc_detach_program(interface, TcAttachType::Egress, "egress_tc");

    let _ = std::process::Command::new("tc")
        .args(["qdisc", "del", "dev", interface, "clsact"])
        .output();

    tc::qdisc_add_clsact(interface).context("failed to add clsact qdisc")?;

    let tc_program: &mut SchedClassifier = ebpf
        .program_mut("egress_tc")
        .context("failed to find egress_tc program")?
        .try_into()
        .context("failed to cast egress_tc to SchedClassifier")?;
    tc_program.load()?;
    tc_program
        .attach(interface, TcAttachType::Egress)
        .context("failed to attach egress TC program")?;

    Ok(())
}

pub fn load_object() -> anyhow::Result<aya::Ebpf> {
    aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))
    .context("failed to load eBPF object")
}

pub fn raise_memlock_limit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}
