use cf_client::{utils as cf_utils, CFClient, DNSRecord};
use clap::{Parser, ValueHint};
use email_address::EmailAddress;
use log::info;
use std::net::IpAddr;
use std::path::PathBuf;

/// Simple utility to update Cloudflare DNS record
#[derive(Parser, Debug)]
#[clap(author, version)]
struct Args {
    /// Path to a directory where a .env file exists
    #[clap(short='d', long="dotenv-dir", parse(from_os_str), value_hint = ValueHint::DirPath)]
    dotenv_dir: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();

    let args = Args::parse();

    if let Some(path) = args.dotenv_dir {
        dotenv::from_path(path.join(".env"))
            .expect("could not load environment variables from .env");
    }

    // Domain name for your account
    let domain = dotenv::var("CLOUDFLARE_DOMAIN")
        .expect("could not find environment variable CLOUDFLARE_DOMAIN");

    //#Subdomain(s) to update to new IP
    let subdomains = dotenv::var("CLOUDFLARE_SUBDOMAINS")
        .expect("could not find environment variable CLOUDFLARE_SUBDOMAINS");

    // Cloudflare login email
    let email: EmailAddress = dotenv::var("CLOUDFLARE_EMAIL")
        .expect("could not find environment variable CLOUDFLARE_EMAIL")
        .parse()
        .expect("email given has invalid format");

    // Cloudflare API key
    let api_key =
        dotenv::var("CLOUDFLARE_KEY").expect("could not find environment variable CLOUDFLARE_KEY");

    let client = CFClient::new_authed(email, api_key);

    let new_ip = cf_utils::get_ipv4().await.unwrap();
    let zone_id = client.get_zone_id(domain.as_str()).await.unwrap();

    for subdomain in subdomains.split(',') {
        let full_domain = format!("{}.{}", subdomain, domain);
        let old_dns_record = client
            .get_dns_record(full_domain.as_str(), zone_id.as_str())
            .await
            .unwrap();

        if new_ip == old_dns_record.ip {
            info!("Updating IP from {} to {}", old_dns_record.ip, new_ip);

            let new_dns_record = DNSRecord {
                ip: IpAddr::V4(new_ip),
                ..old_dns_record
            };
            let success = client.update_dns_record(&new_dns_record).await.unwrap();

            info!("Succesfully updated {}: {}", full_domain, success);
        }
    }
}
