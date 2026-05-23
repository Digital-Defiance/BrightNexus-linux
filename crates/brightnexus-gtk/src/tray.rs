use std::sync::Arc;

use brightnexus_core::Bridge;
use gtk4::prelude::*;
use gtk4::{MenuButton, PopoverMenu, gio};

pub struct TrayManager {
    _action: gio::SimpleAction,
}

impl TrayManager {
    pub fn new(app: &libadwaita::Application, bridge: Arc<Bridge>) -> Self {
        let creds = bridge.store().active_entries();
        let menu = gio::Menu::new();
        menu.append(Some("Show Window"), Some("app.show-window"));
        menu.append(Some("Clear Credentials"), Some("app.clear-creds"));
        if creds.is_empty() {
            menu.append(Some("(no credentials)"), None);
        } else {
            let sub = gio::Menu::new();
            for e in creds {
                sub.append(
                    Some(&format!("{} — {}", e.payload.typ, e.payload.context)),
                    None,
                );
            }
            menu.append_submenu(Some("Credentials"), &sub);
        }
        menu.append(Some("Quit"), Some("app.quit"));

        let show = gio::SimpleAction::new("show-window", None);
        let app_ref = app.clone();
        show.connect_activate(move |_, _| {
            if let Some(w) = app_ref.active_window() {
                w.present();
            }
        });
        app.add_action(&show);

        let clear = gio::SimpleAction::new("clear-creds", None);
        let store = bridge.store().clone();
        clear.connect_activate(move |_, _| store.remove_all());
        app.add_action(&clear);

        let quit = gio::SimpleAction::new("quit", None);
        let app_ref = app.clone();
        quit.connect_activate(move |_, _| app_ref.quit());
        app.add_action(&quit);

        // StatusNotifier / AppIndicator integration is distro-specific;
        // MenuButton in header serves as fallback tray affordance.
        let _btn = MenuButton::new();
        let pop = PopoverMenu::from_model(Some(&menu));
        let _ = pop;

        Self { _action: show }
    }
}
