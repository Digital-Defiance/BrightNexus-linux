use std::sync::Arc;

use brightnexus_core::policy::{self, PeerAttestationMode};
use brightnexus_core::Bridge;
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, CheckButton, Label, Orientation, SpinButton};
use libadwaita as adw;
use libadwaita::prelude::MessageDialogExt;

pub fn open_settings_dialog(bridge: &Arc<Bridge>) {
    let dialog = adw::MessageDialog::new(
        None::<&gtk4::Window>,
        Some("BrightNexus Settings"),
        Some(&format!(
            "Socket: {}\nBridge identity: {}",
            bridge.paths().primary_socket.display(),
            bridge.identity_kind_str()
        )),
    );

    let vbox = GtkBox::new(Orientation::Vertical, 8);
    let enforce = CheckButton::with_label("Enforce peer attestation for LINK_DELIVER");
    enforce.set_active(policy::policy().peer_attestation_mode == PeerAttestationMode::Enforce);
    vbox.append(&enforce);

    let ttl_row = GtkBox::new(Orientation::Horizontal, 8);
    ttl_row.append(&Label::new(Some("Credential TTL ceiling (seconds):")));
    let ttl_spin = SpinButton::with_range(60.0, 28800.0, 60.0);
    ttl_spin.set_value(policy::policy().credential_ttl_ceiling_seconds as f64);
    ttl_row.append(&ttl_spin);
    vbox.append(&ttl_row);

    dialog.set_extra_child(Some(&vbox));
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("save", "Save");
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

    dialog.connect_response(move |dialog: adw::MessageDialog, response: &str| {
        if response == "save" {
            policy::set_peer_attestation_mode(if enforce.is_active() {
                PeerAttestationMode::Enforce
            } else {
                PeerAttestationMode::LogOnly
            });
            policy::set_ttl_ceiling(ttl_spin.value() as i64);
        }
        dialog.close();
    });

    dialog.present();
}

pub fn show_geo_prompt(
    parent: Option<&impl IsA<gtk4::Window>>,
    caller: &str,
    scope: &str,
) -> gtk4::ResponseType {
    let dialog = adw::MessageDialog::new(
        parent,
        Some("BrightLink: Location Request"),
        Some(&format!("{caller}\nRequesting: {scope}")),
    );
    dialog.add_response("deny", "Deny");
    dialog.add_response("once", "Allow Once");
    dialog.add_response("always", "Allow Always");
    dialog.set_default_response(Some("deny"));
    dialog.set_close_response("deny");
    gtk4::ResponseType::Cancel
}
