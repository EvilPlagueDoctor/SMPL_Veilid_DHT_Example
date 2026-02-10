use std::sync::Arc;
use std::io::{self, Write};
use flume::{Sender};
use veilid_core::*;
use tokio::io::AsyncBufReadExt;
use std::fs::File;
use std::fs;

/////////////////////////////////////////////////////////////////////////////////
//
//	1: In the Default node, a DHT is created & can be edited at will.
//	2: The default node will write the nessasary keys to a text file
//	3: In a seperate console, run the application, but as Alternate
//	4: This will read the text file, and allow the second node access to the DHT
//	5: A few examples of DHT monotoring will be presented
//
//	The Two seperate nodes are run inside thier own functions:
//	run_default_node() and run_alt_node()
//      These functions can be found below the main function
//
/////////////////////////////////////////////////////////////////////////////////


// -------------------------------------------------------------------------
// Main Function (Where the program starts)
// -------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

// This First Section is just A selection of what node to launch.
    loop {
        println!("Select Veilid configuration:");
        println!("  Press 1 - Default config");
        println!("  Press 2 - Alternate config");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => {
                println!("Starting DEFAULT node\n");
                run_default_node().await?;
                break;
            }
            "2" => {
                println!("Starting ALTERNATE node\n");
                run_alt_node().await?;
                break;
            }
            _ => {
                println!("Invalid choice, try again.\n");
            }
        }
    }

    Ok(())
}



// -------------------------------------------------------------------------
// Update callback (this gets updated every time something updates/changes in the velid node)
// -------------------------------------------------------------------------

fn u_c(update: VeilidUpdate, ready_tx: Option<Sender<()>>) {
    match update {
        VeilidUpdate::Log(_veilid_log) => {}
        VeilidUpdate::AppMessage(msg) => {
            let text = String::from_utf8_lossy(msg.message());
            println!("AppMessage: {text}");
        }
        VeilidUpdate::AppCall(_veilid_app_call) => {}
        VeilidUpdate::Attachment(att) => {
            if att.public_internet_ready {
                //println!("Veilid is fully ready!");
                if let Some(tx) = ready_tx {
                    // Fire once, ignore error if already sent (to let the program know when I'm fully connected)
                    let _ = tx.send(());
                }
            }
        }
        VeilidUpdate::Network(_veilid_state_network) => {}
        VeilidUpdate::Config(_veilid_state_config) => {println!("Config")}
        VeilidUpdate::RouteChange(veilid_route_change) => {
            println!("{veilid_route_change:?}");
        }
        VeilidUpdate::ValueChange(_veilid_value_change) => {
            println!("DHT ValueChange");
            }
        VeilidUpdate::Shutdown => {println!("ShutDown")}
    }

}


// -------------------------------------------------------------------------
// Default Node Function (if the user selected Number 1 in main)
// -------------------------------------------------------------------------

async fn run_default_node() -> Result<(), Box<dyn std::error::Error>> {
    let (ready_tx, ready_rx) = flume::bounded::<()>(1); // just a variable we injected in the Update callback to let us know when we're fully connected.

// Grab the location from the executable file (depending on the platform, 
// this can be diffrent from where it was launched from)
        let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|x| x.parent().map(|p| p.to_owned()))
        .unwrap_or_else(|| ".".into());

// Here we set up the base configuration of the veilid node (we give this one a diffrent Namespace than the Alt. node)
    let config = VeilidConfig {
        program_name: "Example Veilid".into(),
        namespace: "veilid-example-ver1".into(),

        protected_store: VeilidConfigProtectedStore {
            // IMPORTANT: don't do this in production
            // This avoids prompting for a password and is insecure
            always_use_insecure_storage: true,
            directory: exe_dir
                .join(".veilid/protected_store")
                .to_string_lossy()
                .to_string(),
            ..Default::default()
        },
        table_store: VeilidConfigTableStore {
            directory: exe_dir
                .join(".veilid/table_store")
                .to_string_lossy()
                .to_string(),
            ..Default::default()
        },
        ..Default::default()
    };


// Update Callback, this is our live feed of what the node is doing/incoming messages/etc.
    let update_callback = {
        let ready_tx = ready_tx.clone();
        Arc::new(move |update: VeilidUpdate| {
            u_c(update, Some(ready_tx.clone()));
        })
    };

    let veilid = veilid_core::api_startup(update_callback, config).await?;

// What it says on the tin, with everything set up, we now try to attach to the network.
    veilid.attach().await?;

    println!("Waiting for Veilid to reach full attachment...");
    ready_rx.recv_async().await?;
    println!("Veilid fully attached");


// ------------- Node is Now Setup And attached, from here on is DHT stuff! -----------------------


    let rc = veilid.routing_context()?;

// Create a keypair using VLD0 (only option in version 5.x, although VLD1 is in the works)
    let owner_kp = Crypto::generate_keypair(CRYPTO_KIND_VLD0)?; 

// We split the keypair into it's public and secret constituents. (we don't need secret here so it's _silenced)
    let (owner_public, _owner_secret) = owner_kp.clone().into_split();

// we generate an ID to go with the key we just generated
    let owner_id = veilid.generate_member_id(&owner_public)?;

// veilid wants a bare ID for parts, so we convert the normal ID into a bare ID (no Idea what the diffrence is)
    let bare_owner_id = owner_id.into_value();

// set up what that setup that ID will get set up with in the DHT we're creating.
    let owner_opts = SetDHTValueOptions {
        writer: Some(owner_kp.clone()),
        allow_offline: None,
    };

// set up the schema (what users have access, how many keys, etc)
    let schema = DHTSchema::smpl(
        2,
        vec![DHTSchemaSMPLMember {
            m_key: bare_owner_id.clone(),
            m_cnt: 2,
        }],
    )?;

// just a little check to make sure what we've done checks out so far.
    schema.validate()?;


    let record_desc = rc
        .create_dht_record(CRYPTO_KIND_VLD0, schema.clone(), None)
        .await?;

    let record_key = record_desc.key();

    println!("OwnerPublic = {:?}", owner_public);
    println!("owner_kp = {:?}", owner_kp);
    println!("RecordKey = {:?}", record_key);
    

// --------------------------------------------------
// Write keys to a file next to the executable
// --------------------------------------------------

    println!("txt file loaded");

    let key_file_path = exe_dir.join("owner_keys.txt");
    let mut file = File::create(&key_file_path)?;

    writeln!(file, "owner_kp = {}", owner_kp)?;
    writeln!(file, "RecordKey = {}", record_key)?;

    println!(
    "Owner keys written to {}",
    key_file_path.to_string_lossy()
    );


let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
let mut line = String::new();

let subkey: u32 = 2; // which subkey we're going to write to.

loop {
    println!();
    println!("(You can now open a second console to run the Alt Node)");
    println!("Type text and press ENTER to write to the DHT");
    println!("Or, Press Ctrl+C to exit");
    println!();

    line.clear();

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nCtrl+C received, shutting down...");
            break;
        }

        result = stdin.read_line(&mut line) => {
            let bytes = result?;
            if bytes == 0 {
                // EOF (unlikely in a terminal, but safe)
                break;
            }

            let text = line.trim();
            if text.is_empty() {
                continue;
            }

            rc.set_dht_value(
                record_key.clone(),
                subkey,
                text.as_bytes().to_vec(),
                Some(owner_opts.clone()),
            )
            .await?;

            println!("Wrote to subkey {subkey}: {text}");
	    println!();

        }
    }
}


veilid.shutdown().await;
println!("Shutdown complete (press enter)");

    Ok(())
}




// -------------------------------------------------------------------------
// Alternate Node Function (if the user selected Number 2 in main)
// -------------------------------------------------------------------------

async fn run_alt_node() -> Result<(), Box<dyn std::error::Error>> {

        let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|x| x.parent().map(|p| p.to_owned()))
        .unwrap_or_else(|| ".".into());

// -------------------------------------------------------
// Load up the keys the main node stored in the txt file.
// -------------------------------------------------------
    let path = exe_dir.join("owner_keys.txt");

    if !path.exists() {
        return Err("owner_keys.txt does not exist".into());
    }

    let contents = fs::read_to_string(&path)?;

    if contents.trim().is_empty() {
        return Err("owner_keys.txt is empty".into());
    }


    let mut owner_kp: Option<KeyPair> = None;
    let mut record_key: Option<RecordKey> = None;

    for line in contents.lines() {
        let line = line.trim();


        if let Some(rest) = line.strip_prefix("owner_kp =") {
            owner_kp = Some(rest.trim().parse()?);
        }

	if let Some(rest) = line.strip_prefix("RecordKey =") {
	    record_key = Some(rest.trim().parse()?);
	}
    }

let (owner_kp, record_key) =
    match (owner_kp, record_key) {
        (Some(seck), Some(rk)) => (seck, rk),
        _ => {
            eprintln!("WARNING: owner_keys.txt is missing required keys");
            return Err("owner_keys.txt is missing required keys".into());
        }
    };

// -------------------------------------------------
//    Now we have those key's loaded up, we can continue
// -------------------------------------------------

    let (ready_tx, ready_rx) = flume::bounded::<()>(1);

// Setting up the veilid node (using a diffrent namespace than the other node)
    let config = VeilidConfig {
        program_name: "Example Veilid".into(),
        namespace: "veilid-example-ver2".into(),

        protected_store: VeilidConfigProtectedStore {
            // IMPORTANT: don't do this in production
            // This avoids prompting for a password and is insecure
            always_use_insecure_storage: true,
            directory: exe_dir
                .join(".veilid/protected_store")
                .to_string_lossy()
                .to_string(),
            ..Default::default()
        },
        table_store: VeilidConfigTableStore {
            directory: exe_dir
                .join(".veilid/table_store")
                .to_string_lossy()
                .to_string(),
            ..Default::default()
        },
        ..Default::default()
    };


    let update_callback = {
        let ready_tx = ready_tx.clone();
        Arc::new(move |update: VeilidUpdate| {
            u_c(update, Some(ready_tx.clone()));
        })
    };

    let veilid = veilid_core::api_startup(update_callback, config).await?;
    veilid.attach().await?;

    println!("Alternate node waiting for attachment...");
    ready_rx.recv_async().await?;
    println!("Alternate node ready");


// ------------- Node is Now Setup And attached, from here on is DHT stuff! -----------------------    


    let rc = veilid.routing_context()?;

    // open up the dht record
    let record_desc = veilid.routing_context()?.open_dht_record(
        record_key.clone(),
        Some(owner_kp),
    )
    .await?;

    println!("Opened record: {:?}", record_desc.key());
    println!("Waiting for DHT to become routable...");

    // preforming a DHT record inspection
    let report = loop {
        match rc
            .inspect_dht_record(record_key.clone(), None, DHTReportScope::SyncGet)
            .await
        {
            Ok(r) => break r,
            Err(VeilidAPIError::TryAgain { .. }) => {
                println!("DHT not ready yet, retrying...");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(e) => {
                eprintln!("inspect_dht_record failed: {e:?}");
                return Err(e.into());
            }
        }
    };

    println!("DHT inspection complete: {report:?}");

    // put a watch on the node:
    let watch_active = rc
        .watch_dht_values(record_key.clone(), None, None, None)
        .await?;

    println!("DHT watch active: {watch_active}");
    println!();

println!("Press ENTER to read/re-read the DHT");
println!("Press Ctrl+C to exit");
println!();

let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
let mut line = String::new();

loop {
    line.clear();

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nCtrl+C received, shutting down...");
            break;
        }

        result = stdin.read_line(&mut line) => {
            let bytes = result?;
            if bytes == 0 {
                // EOF (unlikely in terminal, but safe)
                break;
            }

            println!("Reading the DHT...");
            for subkey in [0u32, 1, 2, 3] {
                match rc
                    .get_dht_value(record_key.clone(), subkey, false)
                    .await?
                {
                    Some(value) => {
                        let text = String::from_utf8_lossy(value.data());
                        println!("[read] subkey {subkey}: {text}");
                    }
                    None => {
                        println!("[read] subkey {subkey}: <no data>");
                    }
                }
            }

            println!();
            println!("Press ENTER to refresh, Ctrl+C to exit");
            println!();
        }
    }
}

veilid.shutdown().await;
println!("Shutdown complete (press enter)");

    Ok(())
}
