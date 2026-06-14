use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};
use wirefinder_proto::{
    request, InterfaceStatus, Request, Response, ServerInfo, ServerSpec,
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // A minimal tray: show the window, or quit.
            let show = MenuItem::with_id(app, "show", "Show wirefinder", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;

            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
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
            import_server,
            remove_server,
            list_servers,
            status,
            switch_server,
            disconnect
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}
