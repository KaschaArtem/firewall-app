use anyhow::Context as _;
use inquire::Select;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

pub fn prompt_for_interface() -> anyhow::Result<String> {
    let interfaces = NetworkInterface::show().context("failed to get list of network interfaces")?;

    let iface_names: Vec<String> = interfaces.into_iter().map(|i| i.name).collect();

    if iface_names.is_empty() {
        return Err(anyhow::anyhow!("network interfaces are not found"));
    }

    let selection = Select::new("Choose network interface:", iface_names)
        .with_help_message("↓ ↑ - navigation, ENTER - confirm")
        .prompt()
        .context("error on choosing network interface")?;

    Ok(selection)
}
