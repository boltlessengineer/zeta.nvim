use mlua::prelude::*;
use base64::prelude::*;
use rand::thread_rng;
use rsa::{pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey}, RsaPrivateKey, RsaPublicKey};
use std::convert::TryFrom;
use anyhow::{Context, Result};

struct PublicKey(RsaPublicKey);

impl TryFrom<PublicKey> for String {
    type Error = anyhow::Error;
    fn try_from(key: PublicKey) -> Result<Self> {
        let bytes = key
            .0
            .to_pkcs1_der()
            .context("failed to serialize public key")?;
        let string = BASE64_URL_SAFE.encode(&bytes);
        Ok(string)
    }
}

impl TryFrom<String> for PublicKey {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        let bytes = BASE64_URL_SAFE
            .decode(&value)
            .context("failed to base64-decode public key string")?;
        let key = Self(RsaPublicKey::from_pkcs1_der(&bytes).context("failed to parse public key")?);
        Ok(key)
    }
}

/// creates login url that should be opened from browser
fn url(_: &Lua, _: ()) -> LuaResult<String> {
    let mut rng = thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    Ok(format!("https://zed.dev/native_app_signin?native_app_port=800&native_app_public_key={}", String::try_from(PublicKey(public_key)).unwrap()))
}

#[mlua::lua_module]
fn zeta_auth(lua: &Lua) -> LuaResult<LuaTable> {
    let exports = lua.create_table()?;
    exports.set("url", lua.create_function(url)?)?;
    Ok(exports)
}
