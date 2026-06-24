use katana_tee_client::KatanaRpcClient;
use std::sync::Mutex;

// `KATANA_RPC_URL` is process-global, and cargo runs a binary's tests on parallel
// threads. Serialize the env-mutating tests so they can't interleave (otherwise
// `test_client_from_env` leaves the var set and `test_client_default` flakes),
// and restore the prior value afterwards.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_katana_rpc_url<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("KATANA_RPC_URL").ok();
    match value {
        Some(v) => std::env::set_var("KATANA_RPC_URL", v),
        None => std::env::remove_var("KATANA_RPC_URL"),
    }
    let out = f();
    match prev {
        Some(v) => std::env::set_var("KATANA_RPC_URL", v),
        None => std::env::remove_var("KATANA_RPC_URL"),
    }
    out
}

#[test]
fn test_client_from_env() {
    with_katana_rpc_url(Some("http://test:1234"), || {
        let client = KatanaRpcClient::from_env();
        assert_eq!(client.url(), "http://test:1234");
    });
}

#[test]
fn test_client_default() {
    with_katana_rpc_url(None, || {
        let client = KatanaRpcClient::from_env();
        assert_eq!(client.url(), "http://localhost:5050");
    });
}
