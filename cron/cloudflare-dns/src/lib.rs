use email_address::EmailAddress;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use reqwest::ClientBuilder;
use serde_json::{json, Value};
use std::fmt;
use std::net::IpAddr;

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

fn format_error(msg: &str, details: &impl fmt::Display) -> String {
    format!("{}:\n{}", msg, details)
}

pub mod utils {
    use crate::format_error;
    #[cfg(test)]
    use mockito;
    use reqwest::ClientBuilder;
    use std::net::{IpAddr, Ipv4Addr};

    pub async fn get_ipv4() -> Result<Ipv4Addr, String> {
        let client = ClientBuilder::new()
            .user_agent(super::APP_USER_AGENT)
            .local_address(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
            .build()
            .expect("could not build Client");

        #[cfg(not(test))]
        let url = "https://icanhazip.com";

        #[cfg(test)]
        let url = &mockito::server_url();

        let request = client.get(url).build().expect("could not build request");
        let response = client
            .execute(request)
            .await
            .map_err(|_| -> &'static str { "cannot get current IPv4" })?;

        let response = response
            .text()
            .await
            .expect("could not convert response to text");

        response
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|_| format_error("could not parse response to IPv4 address", &response))
    }
}

pub struct DNSRecord {
    pub domain: String,
    pub zone_id: String,
    pub dns_id: String,
    pub ip: IpAddr,
}

pub struct CFClient {
    client: Client,
}

impl CFClient {
    pub fn new(headers: Option<HeaderMap>) -> Self {
        let mut cbuilder = ClientBuilder::new().user_agent(APP_USER_AGENT);

        if let Some(header_map) = headers {
            cbuilder = cbuilder.default_headers(header_map);
        }

        CFClient {
            client: cbuilder.build().expect("could not build client"),
        }
    }

    pub fn new_authed<TokenType: fmt::Display>(email: EmailAddress, api_key: TokenType) -> Self {
        let mut headers = [
            (
                HeaderName::from_static("x-auth-email"),
                HeaderValue::from_str(email.as_ref())
                    .expect("header value contains invalid characters"),
            ),
            (
                AUTHORIZATION,
                HeaderValue::from_str(format!("Bearer {}", api_key).as_str())
                    .expect("header value contains invalid characters"),
            ),
        ];
        headers[1].1.set_sensitive(true);

        Self::from_iter(headers.into_iter())
    }

    pub async fn get_zone_id(&self, domain: impl fmt::Display) -> Result<String, String> {
        let url = format!("https://api.cloudflare.com/client/v4/zones?name={}&status=active&page=1&per_page=20&order=status&direction=desc&match=all", domain);

        let request = self
            .client
            .get(url)
            .header(CONTENT_TYPE, "application/json")
            .build()
            .expect("could not build request to get Zone ID");

        let response = self
            .client
            .execute(request)
            .await
            .map_err(|_| "cannot get Cloudflare Zone ID")?
            .json::<Value>()
            .await
            .map_err(|_| "response is not valid json")?;

        response
            .pointer("/result/0/id")
            .ok_or_else(|| {
                format_error(
                    "response had unexpected format while getting Zone ID",
                    &response,
                )
            })
            .map(|o| {
                o.as_str()
                    .expect("cannot convert Zone ID to text")
                    .to_string()
            })
    }

    pub async fn get_dns_record(
        &self,
        full_domain: impl fmt::Display,
        zone_id: impl fmt::Display,
    ) -> Result<DNSRecord, String> {
        let url = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=A&name={}&page=1&per_page=20&order=type&direction=desc&match=all", zone_id, full_domain);

        let request = self
            .client
            .get(url)
            .header(CONTENT_TYPE, "application/json")
            .build()
            .expect("could not build request to get DNS record");

        let response = self
            .client
            .execute(request)
            .await
            .map_err(|_| String::from("cannot get DNS record"))?
            .json::<serde_json::Value>()
            .await
            .map_err(|_| String::from("response is not valid json"))?;

        let dns_id = response
            .pointer("/result/0/id")
            .ok_or_else(|| {
                format_error(
                    "response had unexpected format while getting DNS ID:\n{}",
                    &response,
                )
            })
            .map(|o| {
                o.as_str()
                    .expect("cannot convert DNS ID to text")
                    .to_string()
            })?;

        let ip: IpAddr = response
            .pointer("/result/0/content")
            .ok_or_else(|| {
                format_error(
                    "response had unexpected format while getting IP of DNS record",
                    &response,
                )
            })
            .map(|o| {
                o.as_str()
                    .expect("cannot convert IP address field to text")
                    .to_string()
            })?
            .parse()
            .map_err(|_| "cannot parse data into IP address - is this a type A record?")?;

        Ok(DNSRecord {
            domain: full_domain.to_string(),
            zone_id: zone_id.to_string(),
            dns_id,
            ip,
        })
    }

    pub async fn update_dns_record(&self, record: &DNSRecord) -> Result<bool, String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            record.zone_id, record.dns_id
        );

        let data = json!({"type": "A", "name": record.domain, "content": record.ip.to_string()});

        let request = self
            .client
            .put(url)
            .header(CONTENT_TYPE, "application/json")
            .json(&data)
            .build()
            .expect("could not build request to update DNS record");

        Ok(self
            .client
            .execute(request)
            .await
            .map_err(|_| "cannot update DNS record")?
            .json::<serde_json::Value>()
            .await
            .map_err(|_| "response is not valid json")?
            .pointer("/success")
            .ok_or("response had unexpected format while updating DNS ID")?
            .as_bool()
            .expect("response could not be converted to bool"))
    }
}

impl FromIterator<(HeaderName, HeaderValue)> for CFClient {
    fn from_iter<I: IntoIterator<Item = (HeaderName, HeaderValue)>>(iter: I) -> Self {
        Self::new(Some(HeaderMap::from_iter(iter)))
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use mockito::mock;
    use std::net::Ipv4Addr;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_can_get_ipv4() {
        let _m = mock("GET", "/")
            .with_status(201)
            .with_body("     1.2.3.4    ")
            .create();

        assert_eq!(
            "1.2.3.4".parse::<Ipv4Addr>().unwrap(),
            aw!(utils::get_ipv4()).unwrap()
        );
    }
}
