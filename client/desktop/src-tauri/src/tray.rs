use crate::{exit_probe::PublicExit, App, View};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Window, WindowEvent};

const TRAY_ID: &str = "ccproxy-tray";
const SHOW: &str = "ccproxy-tray-show";
const QUIT: &str = "ccproxy-tray-quit";
const MAIN_WINDOW: &str = "main";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub(crate) enum Language {
    #[serde(rename = "en")]
    English,
    #[serde(rename = "zh-Hans")]
    Chinese,
}

impl Language {
    pub(crate) fn preferred() -> Self {
        sys_locale::get_locales()
            .find_map(|locale| match locale.split(['-', '_']).next()? {
                code if code.eq_ignore_ascii_case("en") => Some(Self::English),
                code if code.eq_ignore_ascii_case("zh") => Some(Self::Chinese),
                _ => None,
            })
            .unwrap_or(Self::English)
    }

    fn messages(self) -> &'static Messages {
        match self {
            Self::English => &MESSAGES.english,
            Self::Chinese => &MESSAGES.chinese,
        }
    }
}

#[derive(Deserialize)]
struct Catalog {
    #[serde(rename = "en")]
    english: Messages,
    #[serde(rename = "zh-Hans")]
    chinese: Messages,
}

#[derive(Deserialize)]
struct Messages {
    signed_out: String,
    disconnected: String,
    connecting: String,
    connected: String,
    disconnecting: String,
    failed: String,
    public_exit_ip: String,
    show_window: String,
    quit: String,
}

static MESSAGES: LazyLock<Catalog> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../locales/tray.json")).expect("valid tray translations")
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Connection {
    SignedOut,
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed,
}

impl Connection {
    fn from_view(view: &View) -> Self {
        match (view.signed_in, view.tunnel.as_str(), view.want_connected) {
            (false, _, _) => Self::SignedOut,
            (true, "running", true) => Self::Connected,
            (true, "running" | "starting", false) => Self::Disconnecting,
            (true, "failed", _) => Self::Failed,
            (true, _, true) => Self::Connecting,
            _ => Self::Disconnected,
        }
    }

    fn icon(self) -> tauri::Result<Image<'static>> {
        let png: &[u8] = match self {
            Self::SignedOut => include_bytes!("../icons/tray/signed-out.png"),
            Self::Disconnected => include_bytes!("../icons/tray/disconnected.png"),
            Self::Connecting => include_bytes!("../icons/tray/connecting.png"),
            Self::Connected => include_bytes!("../icons/tray/connected.png"),
            Self::Disconnecting => include_bytes!("../icons/tray/disconnecting.png"),
            Self::Failed => include_bytes!("../icons/tray/failed.png"),
        };
        Image::from_bytes(png)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Snapshot {
    connection: Connection,
    exit_ip: Option<Ipv4Addr>,
    language: Language,
}

impl Snapshot {
    fn read(app: &App) -> Self {
        let view = app.view(false);
        Self::from_view(&view, *app.tray_language.lock().unwrap())
    }

    fn from_view(view: &View, language: Language) -> Self {
        let connection = Connection::from_view(view);
        let exit_ip = match (connection, &view.public_exit) {
            (Connection::Connected, PublicExit::Verified(ip)) => Some(*ip),
            _ => None,
        };
        Self {
            connection,
            exit_ip,
            language,
        }
    }

    fn status(self) -> &'static str {
        let messages = self.language.messages();
        match self.connection {
            Connection::SignedOut => &messages.signed_out,
            Connection::Disconnected => &messages.disconnected,
            Connection::Connecting => &messages.connecting,
            Connection::Connected => &messages.connected,
            Connection::Disconnecting => &messages.disconnecting,
            Connection::Failed => &messages.failed,
        }
    }

    fn description(self, separator: &str) -> String {
        match self.exit_ip {
            Some(ip) => format!(
                "{}{separator}{} {ip}",
                self.status(),
                self.language.messages().public_exit_ip
            ),
            None => self.status().to_owned(),
        }
    }

    fn tooltip(self) -> String {
        format!("aifree\n{}", self.description("\n"))
    }
}

pub(crate) fn install(handle: &AppHandle, app: Arc<App>) -> tauri::Result<()> {
    let initial = Snapshot::read(&app);
    let messages = initial.language.messages();
    let status = MenuItem::new(handle, initial.description(" · "), false, None::<&str>)?;
    let open = MenuItem::with_id(handle, SHOW, &messages.show_window, true, None::<&str>)?;
    let quit = MenuItem::with_id(handle, QUIT, &messages.quit, true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(handle)?;
    let menu = Menu::with_items(handle, &[&status, &separator, &open, &quit])?;
    let tray = TrayIconBuilder::with_id(TRAY_ID)
        .icon(initial.connection.icon()?)
        .icon_as_template(cfg!(target_os = "macos"))
        .tooltip(initial.tooltip())
        .menu(&menu)
        .on_menu_event(|app, event| match event.id.as_ref() {
            SHOW => show_window(app),
            QUIT => app.exit(0),
            _ => {}
        })
        .build(handle)?;

    std::thread::spawn(move || {
        let mut previous = initial;
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let next = Snapshot::read(&app);
            if next == previous {
                continue;
            }
            let update = || -> tauri::Result<()> {
                if next.connection != previous.connection {
                    tray.set_icon_with_as_template(
                        Some(next.connection.icon()?),
                        cfg!(target_os = "macos"),
                    )?;
                }
                status.set_text(next.description(" · "))?;
                if !cfg!(target_os = "linux") {
                    tray.set_tooltip(Some(next.tooltip()))?;
                }
                if next.language != previous.language {
                    let messages = next.language.messages();
                    open.set_text(&messages.show_window)?;
                    quit.set_text(&messages.quit)?;
                }
                Ok(())
            };
            if let Err(error) = update() {
                eprintln!("Could not update the system tray: {error}");
            }
            previous = next;
        }
    });
    Ok(())
}

pub(crate) fn show_window(handle: &AppHandle) {
    if let Some(window) = handle.get_webview_window(MAIN_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub(crate) fn window_event(window: &Window, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        if window.label() == MAIN_WINDOW
            && window.app_handle().tray_by_id(TRAY_ID).is_some()
            && tray_host_available()
            && window.hide().is_ok()
        {
            api.prevent_close();
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn tray_host_available() -> bool {
    true
}

#[cfg(target_os = "linux")]
fn tray_host_available() -> bool {
    use gio::glib::{variant::ToVariant, Variant};
    use gio::{BusType, Cancellable, DBusCallFlags};

    const WATCHER: &str = "org.kde.StatusNotifierWatcher";
    let Ok(bus) = gio::bus_get_sync(BusType::Session, Cancellable::NONE) else {
        return false;
    };
    bus.call_sync(
        Some(WATCHER),
        "/StatusNotifierWatcher",
        "org.freedesktop.DBus.Properties",
        "Get",
        Some(&(WATCHER, "IsStatusNotifierHostRegistered").to_variant()),
        None,
        DBusCallFlags::NONE,
        500,
        Cancellable::NONE,
    )
    .ok()
    .and_then(|response| response.get::<(Variant,)>())
    .and_then(|(registered,)| registered.get::<bool>())
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(signed_in: bool, tunnel: &str, want_connected: bool) -> View {
        View {
            signed_in,
            login_username: None,
            device: String::new(),
            has_assignment: false,
            public_exit: PublicExit::NotConnected,
            tunnel: tunnel.to_owned(),
            tunnel_message: String::new(),
            want_connected,
            message: None,
        }
    }

    #[test]
    fn reports_distinct_icons_for_local_connection_states() {
        let cases = [
            (view(false, "idle", false), Connection::SignedOut),
            (view(true, "stopped", false), Connection::Disconnected),
            (view(true, "connecting", true), Connection::Connecting),
            (view(true, "running", true), Connection::Connected),
            (view(true, "running", false), Connection::Disconnecting),
            (view(true, "failed", true), Connection::Failed),
        ];
        let mut icons = std::collections::HashSet::new();
        for (view, expected) in cases {
            let connection = Connection::from_view(&view);
            assert_eq!(connection, expected);
            assert!(icons.insert(connection.icon().unwrap().rgba().to_vec()));
        }
    }

    #[test]
    fn shows_only_the_verified_exit_address_while_connected() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let mut view = view(true, "running", true);
        view.public_exit = PublicExit::Checking;
        let checking = Snapshot::from_view(&view, Language::English);
        assert_eq!(checking.tooltip(), "aifree\nConnected");

        view.public_exit = PublicExit::Verified(ip);
        let verified = Snapshot::from_view(&view, Language::Chinese);
        assert!(verified.description(" · ").contains(&ip.to_string()));
        assert!(verified
            .tooltip()
            .contains(&Language::Chinese.messages().public_exit_ip));

        view.want_connected = false;
        let stopping = Snapshot::from_view(&view, Language::Chinese);
        assert_eq!(stopping.exit_ip, None);
    }
}
