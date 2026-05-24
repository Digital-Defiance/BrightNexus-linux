use std::sync::Arc;

use brightnexus_core::Bridge;
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Button, Label, Orientation, ScrolledWindow};
use libadwaita as adw;
use libadwaita::prelude::AdwApplicationWindowExt;

use crate::settings;
use crate::tray::TrayManager;

pub fn activate(app: &adw::Application, bridge: Arc<Bridge>) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("BrightNexus for Linux")
        .default_width(900)
        .default_height(640)
        .build();

    let header = adw::HeaderBar::new();
    let settings_btn = Button::with_label("Settings");
    settings_btn.connect_clicked({
        let bridge = Arc::clone(&bridge);
        move |_| {
            settings::open_settings_dialog(&bridge);
        }
    });
    header.pack_end(&settings_btn);

    let stack = adw::ViewStack::new();
    stack.add_titled(&build_dashboard(&bridge), Some("dashboard"), "Dashboard");
    stack.add_titled(&build_credentials(&bridge), Some("credentials"), "Credentials");

    let stack_switcher = adw::ViewSwitcher::new();
    stack_switcher.set_stack(Some(&stack));
    stack_switcher.set_policy(adw::ViewSwitcherPolicy::Wide);

    header.set_title_widget(Some(&stack_switcher));

    let root = GtkBox::new(Orientation::Vertical, 0);
    root.append(&header);
    root.append(&stack);
    window.set_content(Some(&root));

    let _tray = TrayManager::new(app, Arc::clone(&bridge));

    window.present();
}

fn build_dashboard(bridge: &Arc<Bridge>) -> ScrolledWindow {
    let scroll = ScrolledWindow::new();
    let vbox = GtkBox::new(Orientation::Vertical, 12);
    vbox.set_margin_top(24);
    vbox.set_margin_bottom(24);
    vbox.set_margin_start(24);
    vbox.set_margin_end(24);

    let title = Label::new(Some("BrightNexus for Linux"));
    title.add_css_class("title-1");
    vbox.append(&title);

    let kind = Label::new(Some(&format!(
        "Bridge identity: {}",
        bridge.identity_kind_str()
    )));
    kind.set_xalign(0.0);
    vbox.append(&kind);

    let socket = Label::new(Some(&format!(
        "Socket: {}",
        bridge.paths().primary_socket.display()
    )));
    socket.set_xalign(0.0);
    vbox.append(&socket);

    scroll.set_child(Some(&vbox));
    scroll
}

fn build_credentials(bridge: &Arc<Bridge>) -> ScrolledWindow {
    let scroll = ScrolledWindow::new();
    let vbox = GtkBox::new(Orientation::Vertical, 12);
    vbox.set_margin_top(24);
    vbox.set_margin_start(24);
    vbox.set_margin_end(24);

    let clear = Button::with_label("Clear All");
    clear.connect_clicked({
        let store = bridge.store().clone();
        move |_| store.remove_all()
    });
    vbox.append(&clear);

    let entries = bridge.store().active_entries();
    for entry in entries {
        let row = Label::new(Some(&format!(
            "{} @ {}",
            entry.payload.typ, entry.payload.context
        )));
        row.set_xalign(0.0);
        vbox.append(&row);
    }

    scroll.set_child(Some(&vbox));
    scroll
}
