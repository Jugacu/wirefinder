use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};
use wirefinder_proto::{
    request, InterfaceStatus, Request, Response, ServerDetail, ServerInfo, ServerSpec,
};

// Each command unwraps the daemon's tagged Response into the ONE payload the
// frontend cares about. Ok → invoke() promise resolves; Err → it rejects. The
// `_ => unexpected` arm guards against a daemon/proto version skew.
fn unexpected() -> String {
    "unexpected response from daemon".into()
}

#[tauri::command]
fn add_server(server: ServerSpec) -> Result<Vec<ServerInfo>, String> {
    match request(&Request::AddServer { server })? {
        Response::Servers(s) => Ok(s),
        Response::Error(e) => Err(e),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
fn edit_server(server: ServerSpec) -> Result<Vec<ServerInfo>, String> {
    match request(&Request::EditServer { server })? {
        Response::Servers(s) => Ok(s),
        Response::Error(e) => Err(e),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
fn get_server(name: String) -> Result<ServerDetail, String> {
    match request(&Request::GetServer { name })? {
        Response::ServerDetail(d) => Ok(d),
        Response::Error(e) => Err(e),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
fn import_server(name: String, conf: String) -> Result<Vec<ServerInfo>, String> {
    match request(&Request::ImportServer { name, conf })? {
        Response::Servers(s) => Ok(s),
        Response::Error(e) => Err(e),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
fn remove_server(name: String) -> Result<Vec<ServerInfo>, String> {
    match request(&Request::RemoveServer { name })? {
        Response::Servers(s) => Ok(s),
        Response::Error(e) => Err(e),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
fn list_servers() -> Result<Vec<ServerInfo>, String> {
    match request(&Request::ListServers)? {
        Response::Servers(s) => Ok(s),
        Response::Error(e) => Err(e),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
fn status() -> Result<Option<InterfaceStatus>, String> {
    match request(&Request::Status)? {
        Response::Status(s) => Ok(Some(s)),
        Response::Disconnected => Ok(None), // daemon up, tunnel down
        Response::Error(e) => Err(e),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
fn disconnect() -> Result<(), String> {
    match request(&Request::Disconnect)? {
        Response::Disconnected => Ok(()),
        Response::Error(e) => Err(e),
        _ => Err(unexpected()),
    }
}

#[tauri::command]
fn switch_server(name: String) -> Result<String, String> {
    match request(&Request::SwitchServer { name })? {
        Response::Switched { name } => Ok(name),
        Response::Error(e) => Err(e),
        _ => Err(unexpected()),
    }
}

/// Push the current connection summary to the tray. The frontend already polls
/// the daemon, so it owns the formatting and just hands us the lines.
///
/// We surface it two ways because no single mechanism is cross-platform:
///   - the native hover tooltip (macOS/Windows; a no-op on Linux/SNI), and
///   - a disabled header item at the top of the tray menu, which is the only
///     thing Linux trays (e.g. i3's SNI tray) will actually display.
#[tauri::command]
fn set_tray_summary(app: tauri::AppHandle, summary: String) -> Result<(), String> {
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(&summary)); // unsupported on Linux; ignore
    }
    app.state::<TrayStatus>()
        .0
        .set_text(&summary)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Handle to the tray menu's header item so [`set_tray_summary`] can rewrite it.
struct TrayStatus(MenuItem<tauri::Wry>);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Must be registered first: a second launch fires this in the running
        // process (then exits), so we just surface the window we already have.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main(app);
        }))
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // A minimal tray: a (disabled) status header that we keep updated
            // from the frontend, then show-the-window / quit.
            let status =
                MenuItem::with_id(app, "status", "wirefinder — starting…", false, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let show = MenuItem::with_id(app, "show", "Show wirefinder", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&status, &sep, &show, &quit])?;
            // Stash the header so set_tray_summary can rewrite it on each poll.
            app.manage(TrayStatus(status));

            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("wirefinder")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => app.exit(0),
                    "show" => show_main(app),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            add_server,
            edit_server,
            get_server,
            import_server,
            remove_server,
            list_servers,
            status,
            switch_server,
            disconnect,
            set_tray_summary
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}
