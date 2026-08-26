//! Empirical probe for the A-06 direct-ACP adapter (`.planning/ACP-ADAPTER.md`
//! in the ai-native-ide repo, "o que construir" step 4).
//!
//! Question it answers, and nothing else: **when the ACP client advertises
//! `clientCapabilities.fs.{readTextFile,writeTextFile} = true`, does the wrapped
//! agent actually route its file writes through the client's
//! `fs/write_text_file`, or does it keep using its own native file tools?**
//!
//! The whole "the broker is what writes, so the session worktree and its harvest
//! can go away" plan depends on the first answer. If the bridge writes natively,
//! a direct adapter still buys the permission bridge (`approvals = Bridged`) but
//! NOT client-mediated writes, and the worktree stays.
//!
//! Run (this machine: never bare `cargo`, it locks the PC):
//!
//! ```text
//! nice -n 19 cargo run -j 2 --example acp_fs_probe -- claude-agent-acp
//! ```
//!
//! Deliberately NOT a test: it spawns a real agent that talks to a real model.

use agent_client_protocol::schema::v1::{
    ClientCapabilities, ContentBlock, FileSystemCapabilities, InitializeRequest, NewSessionRequest,
    PromptRequest, ReadTextFileRequest, ReadTextFileResponse, RequestPermissionOutcome,
    RequestPermissionRequest, RequestPermissionResponse, SelectedPermissionOutcome,
    SessionNotification, TextContent, WriteTextFileRequest, WriteTextFileResponse,
};
use agent_client_protocol::schema::ProtocolVersion;
use agent_client_protocol::{AcpAgent, Agent, ConnectionTo};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// File the prompt asks the agent to create, relative to the session cwd.
const TARGET_FILE: &str = "probe.txt";
/// Content the prompt asks for — an exact string so we can verify the write.
const TARGET_CONTENT: &str = "HELLO_FROM_ACP";

/// Counters shared with the request handlers. Everything the probe concludes
/// is derived from these plus the on-disk state afterwards.
#[derive(Default)]
struct Tally {
    fs_writes: AtomicUsize,
    fs_reads: AtomicUsize,
    permission_requests: AtomicUsize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber_init();

    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "claude-agent-acp".to_string());

    // A scratch directory that is NOT a git repo and NOT the workspace, so a
    // stray write is obvious and harmless.
    let workdir = std::env::temp_dir().join(format!("acp-fs-probe-{}", std::process::id()));
    std::fs::create_dir_all(&workdir)?;
    println!("== probe workdir: {}", workdir.display());
    println!("== bridge command: {command}");

    let tally = Arc::new(Tally::default());

    let agent = AcpAgent::from_str(&command)?;

    let t_write = tally.clone();
    let t_read = tally.clone();
    let t_perm = tally.clone();
    let write_root = workdir.clone();
    let read_root = workdir.clone();

    let prompt_text = format!(
        "Create a file named {TARGET_FILE} in the current working directory whose \
         entire contents are exactly `{TARGET_CONTENT}` with no trailing newline. \
         Then read that file back and tell me what it contains. Do not create any \
         other files."
    );

    let result = agent_client_protocol::Client
        .builder()
        .name("bastion-acp-fs-probe")
        // --- what the whole probe is about: does this handler ever fire? ---
        .on_receive_request(
            async move |request: WriteTextFileRequest, responder, _cx| {
                t_write.fs_writes.fetch_add(1, Ordering::SeqCst);
                println!(
                    "[fs/write_text_file] path={} bytes={} inside_root={}",
                    request.path.display(),
                    request.content.len(),
                    request.path.starts_with(&write_root)
                );
                // The probe performs the write itself — standing in for what the
                // broker would do — so the agent's turn can complete normally.
                if let Some(parent) = request.path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&request.path, &request.content) {
                    Ok(()) => responder.respond(WriteTextFileResponse::new()),
                    Err(e) => {
                        println!("[fs/write_text_file] LOCAL WRITE FAILED: {e}");
                        responder.respond(WriteTextFileResponse::new())
                    }
                }
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: ReadTextFileRequest, responder, _cx| {
                t_read.fs_reads.fetch_add(1, Ordering::SeqCst);
                println!(
                    "[fs/read_text_file] path={} inside_root={}",
                    request.path.display(),
                    request.path.starts_with(&read_root)
                );
                let content = std::fs::read_to_string(&request.path).unwrap_or_default();
                responder.respond(ReadTextFileResponse::new(content))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: RequestPermissionRequest, responder, _cx| {
                t_perm.permission_requests.fetch_add(1, Ordering::SeqCst);
                println!(
                    "[session/request_permission] {}",
                    serde_json::to_string(&request)
                        .unwrap_or_else(|_| "<unserializable>".to_string())
                );
                // Auto-allow: the probe is measuring the transport, not policy.
                //
                // Pick by `kind`, never by position: `claude-agent-acp@0.70.0`
                // orders its options `[reject, allow, allow_always]`, so
                // `options.first()` is a DENY. (Verified live — the official
                // SDK example's `first()` auto-approve is a deny against this
                // bridge. The real adapter must map
                // `PermissionDecision::Allow` -> `allow_once` and
                // `Deny` -> `reject_once` by kind, and error out if neither
                // kind is offered rather than guessing.)
                let pick = |want: &str| -> Option<_> {
                    request
                        .options
                        .iter()
                        .find(|o| {
                            serde_json::to_value(o.kind)
                                .ok()
                                .and_then(|v| v.as_str().map(|s| s == want))
                                .unwrap_or(false)
                        })
                        .map(|o| o.option_id.clone())
                };
                let chosen = pick("allow_once").or_else(|| pick("allow_always"));
                println!("[session/request_permission] choosing: {chosen:?}");
                match chosen {
                    Some(id) => responder.respond(RequestPermissionResponse::new(
                        RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(id)),
                    )),
                    None => responder.respond(RequestPermissionResponse::new(
                        RequestPermissionOutcome::Cancelled,
                    )),
                }
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_notification(
            async move |notification: SessionNotification, _cx| {
                println!(
                    "[session/update] {}",
                    serde_json::to_string(&notification.update)
                        .unwrap_or_else(|_| "<unserializable>".to_string())
                );
                Ok(())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .connect_with(agent, {
            let workdir = workdir.clone();
            |connection: ConnectionTo<Agent>| async move {
                let init = connection
                    .send_request(
                        InitializeRequest::new(ProtocolVersion::V1).client_capabilities(
                            ClientCapabilities::new().fs(FileSystemCapabilities::new()
                                .read_text_file(true)
                                .write_text_file(true)),
                        ),
                    )
                    .block_task()
                    .await?;
                println!(
                    "[initialize] agent replied: {}",
                    serde_json::to_string(&init).unwrap_or_else(|_| "<unserializable>".to_string())
                );

                let session = connection
                    .send_request(NewSessionRequest::new(PathBuf::from(&workdir)))
                    .block_task()
                    .await?;
                println!("[session/new] id={:?}", session.session_id);

                let prompt = connection
                    .send_request(PromptRequest::new(
                        session.session_id.clone(),
                        vec![ContentBlock::Text(TextContent::new(prompt_text))],
                    ))
                    .block_task()
                    .await?;
                println!(
                    "[session/prompt] stop: {}",
                    serde_json::to_string(&prompt)
                        .unwrap_or_else(|_| "<unserializable>".to_string())
                );
                Ok(())
            }
        })
        .await;

    if let Err(e) = &result {
        println!("== connection ended with error: {e}");
    }

    // ---- verdict -------------------------------------------------------
    let writes = tally.fs_writes.load(Ordering::SeqCst);
    let reads = tally.fs_reads.load(Ordering::SeqCst);
    let perms = tally.permission_requests.load(Ordering::SeqCst);
    let target = workdir.join(TARGET_FILE);
    let on_disk = std::fs::read_to_string(&target).ok();

    println!("\n===== VERDICT =====");
    println!("fs/write_text_file calls   : {writes}");
    println!("fs/read_text_file calls    : {reads}");
    println!("session/request_permission : {perms}");
    println!(
        "{} on disk            : {}",
        TARGET_FILE,
        match &on_disk {
            Some(c) => format!("yes ({} bytes)", c.len()),
            None => "no".to_string(),
        }
    );
    match (writes > 0, on_disk.is_some()) {
        (true, _) => println!(
            "=> CLIENT-MEDIATED WRITES CONFIRMED. The broker can own the write; \
             the session worktree and harvest can go away."
        ),
        (false, true) => println!(
            "=> NATIVE WRITE. The file appeared without a single fs/write_text_file, \
             so the bridge ignored our fs capability. The worktree STAYS; a direct \
             adapter still buys the permission bridge, not client-mediated writes."
        ),
        (false, false) => println!(
            "=> INCONCLUSIVE. No fs/write_text_file and no file — the turn probably \
             did not get far enough. Check the [session/update] lines above."
        ),
    }
    println!("workdir kept for inspection: {}", workdir.display());

    Ok(())
}

/// Minimal stderr tracing so the SDK's own diagnostics are visible without
/// pulling `tracing-subscriber` into the crate's dependency set.
fn tracing_subscriber_init() {
    // The SDK logs via `tracing`; with no subscriber installed those records are
    // simply dropped, which is fine for this probe — every line the probe itself
    // needs is printed explicitly above.
}
