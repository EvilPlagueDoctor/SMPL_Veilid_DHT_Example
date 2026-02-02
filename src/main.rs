use std::sync::Arc;
use veilid_core::*;

// To:Do, add inspect_dht_record and watch_dht_values.

// start the main function (the std::error stuff allows me to use the '?' easily)
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

//************** Setting up the Veilid Node

    // Start of by loading up how we want to configure our node 
    // (the function 'build_veilid_config' is down below)
    let config = build_veilid_config();

    // we want a place for veilid to dump all it's udate messages (network, connection status, messages, etc)
    // so we're sending those updates to our u_c function (short for Update Callback)
    // also veilid_core contains most of the functions and such we need to do most things
    let veilid = veilid_core::api_startup(Arc::new(u_c), config).await?;

    // Now we have the model set up, we'll (attempt to) connect it to the veilid network
    veilid.attach().await?;
    println!("Waiting for full attachment..."); // just to let the user know whats going on.

    // We want to wait till we're fully connected before we continue, for now I'm doing this manually
    // in the u_c function I have a print-line that will notify me when it's fully connected
    // then I can continue on by pressing ctrl and C at the same time (if I do it before then it'll fail)
    tokio::signal::ctrl_c().await?;

//************** Here is where the DHT stuff begins

    // we're going to set up the routing context (object?)
    // the routing context contains all the functions and such we need to set up the DHT
    // (along side the veilid_core (that we gave the variable 'veilid' earlier)
    let rc = veilid.routing_context()?;

    // Now, we need to generate ourselves a key pair that we will later use to read/write a section of the DHT
    // we can generate multiple key pairs if we want multiple users and/or sections
    let owner_kp = Crypto::generate_keypair(CRYPTO_KIND_VLD0)?; // (VLD0 is currently the only crypto kind option)

    // now we split the key pair into it's public and private constituants:
    let (owner_public, owner_secret) = owner_kp.clone().into_split();

    // using the public key we're going to generate ourselves an ID to go with the key pair:
    let owner_id = veilid.generate_member_id(&owner_public)?;

    // Right now the ID is hashed, but we want the raw version, so that's what we're doing here:
    let bare_owner_id = owner_id.into_value();

    // set up the options/rules for the ID we just created:
        let owner_opts = SetDHTValueOptions {
        writer: Some(owner_kp.clone()),
        allow_offline: None,
    };

    // now we're going to set up the amount .. 'lines?' of the DHT this key/user can control:
    let smpl_owner = DHTSchemaSMPLMember {
        m_key: bare_owner_id,
        m_cnt: 2,
    };

    // and finally, setting up the schema with the user(s) and such that we want:
    let schema = DHTSchema::smpl(
        2, // nuber of keys that are exclusive (no owner but the OG creator)
        vec![smpl_owner]
    )?;

    // lets just do a validation to make sure everything checks out before giving it to the network:
    schema.validate()?;

    // lets send some info to the console so we can see a bit what's happening:
    println!("SMPL schema created");
    println!("  max subkey: {}", schema.max_subkey());
    println!("  total subkeys: {}", schema.subkey_count());

    // ------------------------------------------------------------
    // Create DHT record
    // ------------------------------------------------------------

    let record_desc = rc
    .create_dht_record(CRYPTO_KIND_VLD0, schema, None)
    .await?;

    //get the key needed to read/write the DHT 
    let read_key = record_desc.key();

    // because Rust gotta rust, we need to make a clone of the key
    let record_key = read_key.clone();

    // again, just some eye candy for the user to glimpse underneath the hood.
    println!("DHT record created: {read_key:?}");

    //******************************************************
    // Lets Write to the DHT
    //******************************************************

    rc.set_dht_value(
        read_key, // this key is now used up, hence why we had to clone it before.
        2, // which.. line? we want to write to in the DHT
        b"Hello World!".to_vec(), // The message we're going to impart.
        Some(owner_opts), // the identity of the one making the write.
    )
    .await?;

    println!("wrote to subkey 2");

    // Lets try to read the values back:

    for subkey in [0u32, 1u32, 2u32, 3u32] {  // 0,1,2 and 3 in u32 typing.
        let result = rc
            .get_dht_value(record_key.clone(), subkey, false)
            .await?;

        match result {
            Some(value) => {
                let text = String::from_utf8_lossy(value.data());
                println!("[read] subkey {subkey}: {text}");
            }
            None => {
                println!("[read] subkey {subkey}: <no data>");
            }
        }
    }



    // ------------------------------------------------------------
    // Shutdown
    // ------------------------------------------------------------

    veilid.shutdown().await;
    println!("? Shutdown complete");

    Ok(())

}

//**************************************************************************
// This Function loads up all the default states that the node will adapt (you can change this to suit your needs)
//**************************************************************************

fn build_veilid_config() -> VeilidConfig {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|x| x.parent().map(|p| p.to_owned()))
        .unwrap_or_else(|| ".".into());

    VeilidConfig {
        program_name: "SMPL Example".into(),
        namespace: "veilid-smpl-example".into(),
        protected_store: VeilidConfigProtectedStore {
            always_use_insecure_storage: true, // dev only
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
    }
}



//*********************************************************
// This function is called at every node update letting you know of any important things
// Like, incoming messages, your attachment state, etc.
//*********************************************************

fn u_c(update: VeilidUpdate) {
        match update {
        VeilidUpdate::Log(_veilid_log) => {println!("Log")}
        VeilidUpdate::AppMessage(veilid_app_message) => {
            let msg = String::from_utf8_lossy(veilid_app_message.message());
            println!("AppMessage received: {msg}");
        }
        VeilidUpdate::AppCall(_veilid_app_call) => {println!("AppCall")}
        VeilidUpdate::Attachment(veilid_state_attachment) => {
            //let state_num = veilid_state_attachment.state as u8;
            //println!("Attachment state = {}", state_num);
	    if veilid_state_attachment.state.is_attached() {
		println!("Youre Attached");
	}
        }
        VeilidUpdate::Network(_veilid_state_network) => {}
        VeilidUpdate::Config(_veilid_state_config) => {println!("Config")}
        VeilidUpdate::RouteChange(veilid_route_change) => {
            // XXX: If this happens, the route is dead, and a new one should be generated and
            // exchanged. This will no longer be necessary after DHT Route Autopublish is implemented in veilid-core v0.6.0
            println!("{veilid_route_change:?}");
        }
        VeilidUpdate::ValueChange(_veilid_value_change) => {println!("ValueChange")}
        VeilidUpdate::Shutdown => {println!("ShutDown")}
    }

}
