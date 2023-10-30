#![no_main]

use libfuzzer_sys::fuzz_target;

#[macro_use]
extern crate lazy_static;

use std::net::SocketAddr;

use std::sync::Mutex;

const MAX_BUF_SIZE: usize = 65507;

lazy_static! {
    static ref CONFIG: Mutex<quiche::Config> = {
        let crt_path = std::env::var("QUICHE_FUZZ_CRT")
            .unwrap_or_else(|_| "fuzz/cert.crt".to_string());
        let key_path = std::env::var("QUICHE_FUZZ_KEY")
            .unwrap_or_else(|_| "fuzz/cert.key".to_string());

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config.load_cert_chain_from_pem_file(&crt_path).unwrap();
        config.load_priv_key_from_pem_file(&key_path).unwrap();
        config
            .set_application_protos(&[b"hq-23", b"http/0.9"])
            .unwrap();
        config.set_initial_max_data(300);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(300);
        config.set_initial_max_streams_bidi(300);
        config.set_initial_max_streams_uni(300);

        Mutex::new(config)
    };
}

static SCID: quiche::ConnectionId<'static> =
    quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
static CCID: quiche::ConnectionId<'static> =
    quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);

fuzz_target!(|data: &[u8]| {
    let from: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let to: SocketAddr = "127.0.0.1:4321".parse().unwrap();

    let mut _buf = data.to_vec();
    let mut out = [0; MAX_BUF_SIZE];

    let mut sconn =
        quiche::accept(&SCID, None, to, from, &mut CONFIG.lock().unwrap())
            .unwrap();

    let sinfo = quiche::RecvInfo { from, to };
    
    let mut cconn = quiche::connect(
        None,
        &CCID,
        from.clone(),
        to.clone(),
        &mut CONFIG.lock().unwrap(),
    )
    .unwrap();

    let cinfo = quiche::RecvInfo { to, from };

    let mut hs_rtt: u8 = 0;
    // handshake loop
    loop {
        let mut pending = 2;

        match cconn.send(&mut out) {
	        Ok(_v) => {
	            sconn.recv(&mut out, sinfo).ok();
	            hs_rtt += 1;
	        },

            Err(quiche::Error::Done) => {
                pending -= 1;
            },
            
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            },
        };

        match sconn.send(&mut out) {
	        Ok(_v) => {
	            cconn.recv(&mut out, cinfo).ok();
	            hs_rtt += 1;
	        },
	        
	        Err(quiche::Error::Done) => {
	            pending -= 1;
	        },
	        
	        Err(e) => {
                eprintln!("Error: {}", e);
                break;
            },
        };
        
        if pending == 0 {
            println!("Handshake Rtt: {}", hs_rtt);
            break;
        }
    
    }
    
});