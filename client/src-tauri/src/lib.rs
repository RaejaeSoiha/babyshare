#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  use std::io::Write;
  use std::sync::Mutex;
  use tauri::Manager;
  use tauri_plugin_shell::ShellExt;
  use tauri_plugin_shell::process::CommandEvent;

  struct BackendSidecar(Mutex<Option<tauri_plugin_shell::process::CommandChild>>);
  struct BackendSystem(Mutex<Option<std::process::Child>>);

  fn log_line(path: &std::path::Path, message: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
      let _ = writeln!(file, "{}", message);
    }
  }

  let app = tauri::Builder::default()
    .setup(|app| {
      let data_dir = app.path().app_data_dir()?;
      std::fs::create_dir_all(&data_dir).ok();
      let data_dir_str = data_dir.to_string_lossy().to_string();
      let resource_dir = app.path().resource_dir()?;
      let resource_dir_str = resource_dir.to_string_lossy().to_string();
      let dist_dir_str = resource_dir.join("dist").to_string_lossy().to_string();
      let log_path = data_dir.join("babyshare-desktop.log");
      log_line(&log_path, "Starting BabyShare desktop app...");

      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }

      let port = "3100";
      let http_port = "3101";
      let frontend_base = if cfg!(debug_assertions) {
        Some("http://localhost:3000")
      } else {
        None
      };
      let mut sidecar_child: Option<tauri_plugin_shell::process::CommandChild> = None;
      if !cfg!(debug_assertions) {
        if let Ok(mut cmd) = app.handle().shell().sidecar("babyshare-server") {
          cmd = cmd
            .env("BBS_ROOT_DIR", &resource_dir_str)
            .env("BBS_DATA_DIR", &data_dir_str)
            .env("BBS_DIST_DIR", &dist_dir_str)
            .env("BBS_DESKTOP", "true")
            .env("FRONTEND_BASE_URL", frontend_base.unwrap_or(""))
            .env("NODE_ENV", "production")
            .env("PORT", port)
            .env("HTTP_PORT", http_port)
            .env("FORCE_HTTPS", "false")
            .env("SHARE_USE_HTTPS", "false");
          match cmd.spawn() {
            Ok((mut rx, child)) => {
              log_line(&log_path, "Sidecar spawn ok (tauri shell).");
              let log_path_clone = log_path.clone();
              tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                  match event {
                    CommandEvent::Stdout(line) => {
                      log_line(&log_path_clone, &format!("sidecar stdout: {}", String::from_utf8_lossy(&line)));
                    }
                    CommandEvent::Stderr(line) => {
                      log_line(&log_path_clone, &format!("sidecar stderr: {}", String::from_utf8_lossy(&line)));
                    }
                    CommandEvent::Error(err) => {
                      log_line(&log_path_clone, &format!("sidecar error: {}", err));
                    }
                    CommandEvent::Terminated(payload) => {
                      log_line(
                        &log_path_clone,
                        &format!(
                          "sidecar terminated: code={:?}, signal={:?}",
                          payload.code, payload.signal
                        ),
                      );
                    }
                    _ => {}
                  }
                }
              });
              sidecar_child = Some(child);
            }
            Err(err) => {
              log_line(&log_path, &format!("Sidecar spawn failed (tauri shell): {err}"));
            }
          }
        }
      } else {
        log_line(&log_path, "Debug build: skipping sidecar and starting node server.");
      }

      let mut system_child: Option<std::process::Child> = None;
      if sidecar_child.is_none() {
        let arch = std::env::consts::ARCH;
        let os = std::env::consts::OS;
        let triple = match (os, arch) {
          ("windows", "x86_64") => "x86_64-pc-windows-msvc",
          ("windows", "aarch64") => "aarch64-pc-windows-msvc",
          ("macos", "x86_64") => "x86_64-apple-darwin",
          ("macos", "aarch64") => "aarch64-apple-darwin",
          ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
          ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
          _ => "unknown",
        };
        let ext = if os == "windows" { ".exe" } else { "" };
        let candidates = [
          resource_dir.join("binaries").join(format!("babyshare-server-{triple}{ext}")),
          resource_dir.join(format!("babyshare-server-{triple}{ext}")),
          resource_dir.join("binaries").join(format!("babyshare-server{ext}")),
          resource_dir.join(format!("babyshare-server{ext}")),
        ];
        for candidate in candidates {
          if candidate.exists() {
            let mut cmd = std::process::Command::new(candidate);
            cmd.env("BBS_ROOT_DIR", &resource_dir_str)
              .env("BBS_DATA_DIR", &data_dir_str)
              .env("BBS_DIST_DIR", &dist_dir_str)
              .env("BBS_DESKTOP", "true")
              .env("FRONTEND_BASE_URL", frontend_base.unwrap_or(""))
              .env("NODE_ENV", "production")
              .env("PORT", port)
              .env("HTTP_PORT", http_port)
              .env("FORCE_HTTPS", "false")
              .env("SHARE_USE_HTTPS", "false");
            match cmd.spawn() {
              Ok(child) => {
                log_line(&log_path, "Sidecar spawn ok (direct path).");
                system_child = Some(child);
                break;
              }
              Err(err) => {
                log_line(&log_path, &format!("Sidecar spawn failed (direct path): {err}"));
              }
            }
          }
        }
      }

      if sidecar_child.is_none() && system_child.is_none() {
        log_line(&log_path, "Sidecar not found or failed to spawn. Falling back to node if available.");
      }
      if sidecar_child.is_none() && system_child.is_none() {
        let mut dir = std::env::current_dir().ok();
        let mut server_js = None;
        for _ in 0..6 {
          if let Some(d) = &dir {
            let candidate = d.join("server.js");
            if candidate.exists() {
              server_js = Some(candidate);
              break;
            }
            dir = d.parent().map(|p| p.to_path_buf());
          }
        }

        if let Some(server) = server_js {
          let workdir = server.parent().unwrap_or_else(|| std::path::Path::new("."));
          let server_path = server.clone();
          let child = std::process::Command::new("node")
            .arg(server_path)
            .current_dir(workdir)
            .env("BBS_ROOT_DIR", &resource_dir_str)
            .env("BBS_DATA_DIR", &data_dir_str)
            .env("BBS_DIST_DIR", &dist_dir_str)
            .env("BBS_DESKTOP", "true")
            .env("FRONTEND_BASE_URL", frontend_base.unwrap_or(""))
            .env("NODE_ENV", "production")
            .env("PORT", port)
            .env("HTTP_PORT", http_port)
            .env("FORCE_HTTPS", "false")
            .env("SHARE_USE_HTTPS", "false")
            .spawn()
            .ok();
          if child.is_some() {
            log_line(&log_path, "Fallback node server spawn ok.");
          } else {
            log_line(&log_path, "Fallback node server spawn failed.");
          }
          system_child = child;
        }
      }

      app.manage(BackendSidecar(Mutex::new(sidecar_child)));
      app.manage(BackendSystem(Mutex::new(system_child)));

      if !cfg!(debug_assertions) {
        let handle = app.handle().clone();
        let port = port.to_string();
        std::thread::spawn(move || {
          use std::net::TcpStream;
          use std::time::Duration;

          for _ in 0..40 {
            if TcpStream::connect_timeout(
              &format!("127.0.0.1:{}", port).parse().unwrap(),
              Duration::from_millis(200),
            )
            .is_ok()
            {
              if let Some(window) = handle.get_webview_window("main") {
                let _ = window.eval(&format!("window.location.replace('http://localhost:{}')", port));
              }
              break;
            }
            std::thread::sleep(Duration::from_millis(250));
          }
        });
      }
      Ok(())
    })
    .plugin(tauri_plugin_shell::init())
    .build(tauri::generate_context!())
    .expect("error while building tauri application");

  app.run(|app_handle: &tauri::AppHandle, event| {
    if let tauri::RunEvent::ExitRequested { .. } = event {
      if let Some(state) = app_handle.try_state::<BackendSidecar>() {
        if let Ok(mut guard) = state.0.lock() {
          if let Some(child) = guard.take() {
            let _ = child.kill();
          }
        }
      }
      if let Some(state) = app_handle.try_state::<BackendSystem>() {
        if let Ok(mut guard) = state.0.lock() {
          if let Some(mut child) = guard.take() {
            let _ = child.kill();
          }
        }
      }
    }
  });
}
