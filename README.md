# aliyun-acm

The Aliyun ACM SDK for Rust.

The library uses [reqwest](https://github.com/seanmonstar/reqwest) and hence is fully asynchronous.

## Quick start

```code
// Create the group you're interested in.
let group = AcmGroup{
  access_key: String::from("access_key"),
  secret_key: String::from("secret_key"),
  namespace: String::from("namespace"),
  group: String::from("group),
};

// Create an Acm instance listening to zero or more acm entries.
let acm = Acm::new("acm.aliyun.com:8080".into(), group, vec!["com.example.app".into()])
  .await
  .unwrap();
  
// Wait for new config. The config is always recognized as new before the first successful wait.
let (id, config) = acm.wait_for_new_config().await.unwrap();
assert!(id == "com.example.app");

// You need to manually refresh acm server ip address if it expired after instance creation.
acm.refresh_acm_server().await.unwrap();
```
