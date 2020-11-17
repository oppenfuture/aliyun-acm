use std::net::Ipv4Addr;
use std::sync::Mutex;
use bytes::Bytes;
use md5::Digest;

mod error;
pub use error::*;

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct AcmGroup {
  pub access_key: String,
  pub secret_key: String,
  pub namespace: String,
  pub group: String,
}

// library interface
pub struct Acm {
  address_server: String,
  acm_server: Mutex<Ipv4Addr>,
  group: AcmGroup,
  current_config: std::collections::HashMap<String, Mutex<String>>,
}

impl Acm {
  // Create a new acm instance listening to zero or more acm entries.
  pub async fn new(
    address_server: String,
    group: AcmGroup,
    ids: Vec<String>,
  ) -> Result<Acm> {
    let acm_server = get_acm_server(&address_server).await?;

    let mut acm = Acm {
      address_server,
      acm_server: Mutex::new(acm_server),
      group,
      current_config: Default::default(),
    };

    for id in ids {
      acm.current_config.insert(id, Mutex::new("".into()));
    }

    Ok(acm)
  }

  // Return the reference to the updated acm entry,
  // and the new config data.
  pub async fn wait_for_new_config(&self) -> Result<(&str, Bytes)> {
    loop {
      match self.add_listener().await? {
        Some(id) => {
          let config = self.get_config(id).await?;
          self.update_md5(id, &config);
          break Ok((id, config))
        },
        None => log::debug!(
          "No new config for namespace {:?} group {:?}",
          self.group.namespace, self.group.group
        ),
      };
    }
  }

  // The ACM server ip address may expire.
  // Upon wait_for_new_config error, user should try to refresh the server address.
  pub async fn refresh_acm_server(&self) -> Result<()> {
    let acm_server = get_acm_server(&self.address_server).await?;
    *self.acm_server.lock().unwrap() = acm_server;
    Ok(())
  }
}
// library interface

// private methods
impl Acm {
  // Send getConfig request.
  async fn get_config(&self, id: &str) -> Result<Bytes> {
    let url = format!("http://{}:8080/diamond-server/config.co", self.acm_server.lock().unwrap());
    let request = reqwest::Client::new().get(&url);
    let request = self.header(request).query(&[
      ("tenant", self.group.namespace.as_str()),
      ("group", self.group.group.as_str()),
      ("dataId", id),
    ]);

    Ok(request
      .timeout(std::time::Duration::from_secs(5))
      .send()
      .await?
      .error_for_status()?
      .bytes()
      .await?
    )
  }

  // Send add listener request and parse the response
  async fn add_listener(&self) -> Result<Option<&str>> {
    let url = format!("http://{}:8080/diamond-server/config.co", self.acm_server.lock().unwrap());
    let request = reqwest::Client::new().post(&url);
    let request = self.header(request).form(&[
      ("Probe-Modify-Request", &self.encode_acm_entries())
    ]);

    let response = request
      .timeout(std::time::Duration::from_secs(40))
      .send()
      .await?
      .error_for_status()?
      .text()
      .await?;

    Ok(if response.is_empty() {
      None
    } else {
      self.decode_acm_entry(&response)
    })
  }

  // Dump common headers to request.
  fn header(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let now = std::time::SystemTime::now();
    let timestamp = match now.duration_since(std::time::UNIX_EPOCH) {
      Ok(duration) => duration,
      Err(e) => e.duration(),
    }.as_millis().to_string();

    let message = self.group.namespace.clone() + "+" + &self.group.group + "+" + &timestamp;
    let signature = hmacsha1::hmac_sha1(self.group.secret_key.as_bytes(), message.as_bytes());
    let signature = base64::encode(signature);

    request.header("Spas-AccessKey", &self.group.access_key)
      .header("timeStamp", &timestamp)
      .header("Spas-Signature", &signature)
      .header("longPullingTimeout", "30000")
  }

  // Udpate stored md5 based on config data, interior mutability pattern.
  fn update_md5(&self, id: &str, bytes: &[u8]) {
    let mut hasher = md5::Md5::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let digest = hex::encode(digest);
    *self.current_config.get(id).unwrap().lock().unwrap() = digest;
  }

  // Encode acm entries.
  // TODO: use GBK encoding?
  fn encode_acm_entries(&self) -> String {
    let mut message = String::new();
    let config_separator = std::char::from_u32(1).unwrap();
    for (id, md5) in self.current_config.iter() {
      let separator = std::char::from_u32(2).unwrap();
      message += id;
      message.push(separator);
      message += &self.group.group;
      message.push(separator);
      message += &*md5.lock().unwrap();
      message.push(separator);
      message += &self.group.namespace;
      message.push(config_separator);
    }
    message
  }

  // Decode the first acm entry in this Acm instance
  // TODO: confirm response encoding
  fn decode_acm_entry(&self, message: &str) -> Option<&str> {
    for config in message.split("%01") {
      let id_group_namespace: Vec<&str> = config.split("%02").collect();

      if id_group_namespace.len() != 3 {
        log::error!("Corrupted response {:?} from add listener", config);
        continue;
      }

      let entry = self.current_config.get_key_value(id_group_namespace[0]);
      if entry.is_none() {
        log::error!("Add listener response id {:?} does not exist", id_group_namespace[0]);
        continue;
      }

      if id_group_namespace[1] != &self.group.group {
        log::error!(
          "Add listener response group {:?} does not match {:}",
          id_group_namespace[1], &self.group.group
        );
        continue;
      }

      if id_group_namespace[2] != &self.group.namespace {
        log::error!(
          "Add listener response namespace {:?} does not match {:}",
          id_group_namespace[2], &self.group.namespace
        );
        continue;
      }

      return Some(entry.unwrap().0);
    }

    None
  }
}
// private methods

// helper functions
async fn get_acm_server(address_server: &str) -> Result<Ipv4Addr> {
  let address_url = format!("http://{}/diamond-server/diamond", address_server);
  let address = reqwest::Client::new().get(&address_url)
    .timeout(std::time::Duration::from_secs(5))
    .send()
    .await?
    .error_for_status()?
    .text()
    .await?;
  let address = address.split("\n").next().unwrap_or("");
  address.parse().map_err(|_| {
    let message = format!("{} is not a valid ipv4 address", address);
    Error::Custom(message)
  })
}
// helper functions

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test() {
      let mut access_key = None;
      let mut secret_key = None;
      let mut namespace = None;
      for (key, value) in std::env::vars() {
        match key.as_str() {
          "NACOS_ACCESS_KEY" => access_key = Some(value),
          "NACOS_SECRET_KEY" => secret_key = Some(value),
          "NACOS_NAMESPACE" => namespace = Some(value),
          _ => (),
        }
      }

      let access_key = access_key.unwrap();
      let secret_key = secret_key.unwrap();
      let namespace = namespace.unwrap();
      let group = crate::AcmGroup{
        access_key,
        secret_key,
        namespace,
        group: "DEFAULT_GROUP".into(),
      };

      let acm = crate::Acm::new(
        "acm.aliyun.com:8080".into(),
        group,
        vec!["com.oppentech.ysl-custom-design.renderer".into()],
      ).await.unwrap();

      acm.wait_for_new_config().await.unwrap();
      assert!(acm.add_listener().await.unwrap().is_none());
    }
}
