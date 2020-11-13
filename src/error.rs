#[derive(Debug)]
pub enum Error {
  Custom(String),
  ReqwestError(reqwest::Error),
  AddrParseError(std::net::AddrParseError),
}

impl std::fmt::Display for Error {
  fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
    match self {
      Error::Custom(e) => e.fmt(formatter),
      Error::ReqwestError(e) => e.fmt(formatter),
      Error::AddrParseError(e) => e.fmt(formatter),
    }
  }
}

impl std::error::Error for Error {}

impl From<String> for Error {
  fn from(e: String) -> Self {
    Error::Custom(e)
  }
}

impl From<reqwest::Error> for Error {
  fn from(e: reqwest::Error) -> Self {
    Error::ReqwestError(e)
  }
}

impl From<std::net::AddrParseError> for Error {
  fn from(e: std::net::AddrParseError) -> Self {
    Error::AddrParseError(e)
  }
}

pub type Result<T> = std::result::Result<T, Error>;
