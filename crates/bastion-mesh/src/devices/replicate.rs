//! Keeps replica nodes up to date (BMD-16): every new event goes to every
//! connected replica node, and a node that (re)connects first receives what
//! it missed since the last `seq` it acknowledged.

use std::sync::Arc;

use tokio::sync::broadcast::error::RecvError;

use super::hub::{HubEvent, PrimaryHub};
use super::log::EventLog;

/// Run until the hub and the log go away. Events a node already holds are
/// skipped by its store, so a catch-up racing a live batch is harmless.
pub fn spawn(hub: PrimaryHub, log: Arc<EventLog>) -> tokio::task::JoinHandle<()> {
    let mut events = log.subscribe();
    let mut hub_events = hub.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = events.recv() => match event {
                    Ok(event) => hub.broadcast_replica(event.seq, vec![event]).await,
                    // Too far behind: every connected replica catches up.
                    Err(RecvError::Lagged(_)) => {
                        for device in hub.connected().await {
                            catch_up(&hub, &log, &device).await;
                        }
                    }
                    Err(RecvError::Closed) => return,
                },
                event = hub_events.recv() => match event {
                    Ok(HubEvent::Connected { device }) => catch_up(&hub, &log, &device).await,
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return,
                },
            }
        }
    })
}

async fn catch_up(hub: &PrimaryHub, log: &EventLog, device: &super::DeviceId) {
    let holds = hub
        .registry()
        .read()
        .await
        .active(device)
        .is_ok_and(|r| r.enrollment.holds_replica);
    if !holds {
        return;
    }
    let after = hub.replica_seq(device).await;
    match log.since(after) {
        Ok(missed) if !missed.is_empty() => {
            let from = missed[0].seq;
            hub.send_replica(device, from, missed).await;
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(event = "replica_catch_up_failed", device = %device, error = %e),
    }
}
