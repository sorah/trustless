// Ported from https://github.com/sorah/mairu/blob/main/src/ppid.rs

#[cfg(unix)]
pub async fn wait_for_parent_process_die(parent: nix::unistd::Pid) -> Result<(), crate::Error> {
    use tokio_stream::StreamExt;

    let (signal, has_signal) = {
        let can_signal = match subscribe_parent_process_die_as_signal() {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(err = ?e, "Failed to subscribe parent process exit as signal");
                false
            }
        };
        if can_signal {
            match tokio::signal::unix::signal(PDEATHSIG_TOKIO) {
                Ok(s) => (future_maybe_signal(Some(s)), true),
                Err(e) => {
                    tracing::warn!(err = ?e, "Failed to monitor for SIGUSR1 (to detect executor process exit)");
                    (future_maybe_signal(None), false)
                }
            }
        } else {
            (future_maybe_signal(None), false)
        }
    };

    let ppid_monitor = monitor_ppid(parent, has_signal);

    tokio::pin!(signal);
    tokio::pin!(ppid_monitor);
    loop {
        tokio::select! {
            sig = signal.next(), if has_signal  => {
                if sig.is_some() {
                    tracing::debug!("parent die notified via signal");
                    break;
                }
            },
            _ = &mut ppid_monitor => {
                break;
            }
        }
    }
    Ok(())
}

fn future_maybe_signal(
    maybe: Option<tokio::signal::unix::Signal>,
) -> impl futures_core::stream::Stream<Item = Option<()>> {
    use tokio_stream::StreamExt;
    async_stream::stream! {
        match maybe {
            Some(sig) => {
                let mut s = tokio_stream::wrappers::SignalStream::new(sig);
                while let Some(s) = s.next().await {
                    yield Some(s);
                }
            }
            None =>  yield None,
        }
    }
}

#[cfg(unix)]
async fn monitor_ppid(parent: nix::unistd::Pid, is_efficient: bool) {
    let interval = tokio::time::Duration::from_secs(if is_efficient { 20 } else { 3 });
    loop {
        if parent != nix::unistd::getppid() {
            break;
        }
        tokio::time::sleep(interval).await;
    }
    tracing::debug!("monitor_ppid detected parent die");
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        fn subscribe_parent_process_die_as_signal() -> Result<bool, std::io::Error> {
            nix::sys::prctl::set_pdeathsig(PDEATHSIG)?;
            Ok(true)
        }
    } else {
        #[inline]
        fn subscribe_parent_process_die_as_signal() -> Result<bool, std::io::Error> {
            Ok(false)
        }
    }
}

static PDEATHSIG: nix::sys::signal::Signal = nix::sys::signal::Signal::SIGUSR1;
static PDEATHSIG_TOKIO: tokio::signal::unix::SignalKind =
    tokio::signal::unix::SignalKind::from_raw(PDEATHSIG as i32);
