//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): this transport held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the module,
//! alone, one test at a time
//! (`cargo test --test measured --all-features -- --test-threads=1`), so
//! what is measured is Xmip's work and not its neighbors':
//!
//! - a thousand writes on one session take a millisecond each at most;
//! - a thousand receives on one session take a millisecond each at most.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use transport::Transport;
use xmip_core_transport_opc_ua::{NodeId, OpcUaTransport};

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn node() -> NodeId {
    NodeId::string(2, "Orders")
}

/// The far end and the near end that opens a session on it.
fn ends() -> (OpcUaTransport, std::net::TcpListener, OpcUaTransport) {
    let far_end =
        OpcUaTransport::new("opc.tcp://127.0.0.1:0/plant", node()).timing_out_after(secs(5));
    let (listener, address) = far_end.bind().expect("binding");
    let near =
        OpcUaTransport::new(format!("opc.tcp://{address}/plant"), node()).timing_out_after(secs(5));
    (far_end, listener, near)
}

#[test]
fn a_thousand_writes_take_a_millisecond_each_at_most() {
    const SENDS: usize = 1000;
    let (far_end, listener, near) = ends();
    let sender = std::thread::spawn(move || {
        let began = Instant::now();
        for n in 0..SENDS {
            near.send("ns=2;s=Orders", n.to_string().as_bytes())?;
        }
        let took = began.elapsed();
        // Generous for a debug build under load: a millisecond a write.
        assert!(took < Duration::from_millis(SENDS as u64), "{took:?}");
        Ok::<_, transport::TransportError>(())
    });
    let mut session = far_end.accept_one(&listener).expect("accepting");
    for n in 0..SENDS {
        let written = session.next_write().expect("write").expect("one");
        assert_eq!(written.bytes, n.to_string().as_bytes());
    }
    sender.join().expect("thread").expect("sending");
}

#[test]
fn a_thousand_receives_take_a_millisecond_each_at_most() {
    const RECEIVES: usize = 1000;
    let (far_end, listener, near) = ends();
    let receiver = std::thread::spawn(move || {
        let began = Instant::now();
        for _ in 0..RECEIVES {
            assert_eq!(near.receive()?.len(), 1);
        }
        let took = began.elapsed();
        // Generous for a debug build under load: a millisecond a receive.
        assert!(took < Duration::from_millis(RECEIVES as u64), "{took:?}");
        Ok::<_, transport::TransportError>(())
    });
    let mut values = BTreeMap::new();
    values.insert(node(), b"ISA*00*".to_vec());
    // Served until the near end lets its session go.
    let mut session = far_end
        .accept_one(&listener)
        .expect("accepting")
        .with_values(values);
    while session.next_event().expect("served").is_some() {}
    receiver.join().expect("thread").expect("received");
}
