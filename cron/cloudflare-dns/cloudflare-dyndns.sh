#!/usr/bin/env sh

#####################################
#      Cloudflare DynDNS Tool       #
#===================================#
# This tool automatically updates   #
# the DNS A record for a subdomain  #
# in a Cloudflare account to the    #
# current IP address of the         #
# computer. Run this on your home   #
# network on a schedule and your    #
# home DNS entry will always be     #
# up to date.                       #
#####################################


set -e

DOMAIN=<cloudflare-domain>      # Domain name for your account
SUBDOMAIN_LIST=(        # Subdomain(s) to update to new IP
                        # - Can also be passed as an argument to the script
    <cloudflare-subdomains>
)
EMAIL=<cloudflare-email> # Cloudflare login email
API_KEY=<cloudflare-key> # Cloudflare API key

if [ ! -z "$1" ]; then
    SUBDOMAIN_LIST=("$1");
fi

if [ -z "$(command -v jq)" ]; then
    echo "You must install the 'jq' tool";
    exit 1;
fi

NEW_IP=$(curl -4 -s -X GET "https://icanhazip.com");

ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN&status=active&page=1&per_page=20&order=status&direction=desc&match=all" \
     -H "X-Auth-Email: $EMAIL" \
     -H "Authorization: Bearer $API_KEY" \
     -H "Content-Type: application/json" | jq -r ".result[].id")


IDX=0
while [ "x${SUBDOMAIN_LIST[IDX]}" != "x" ]
do
    SUBDOMAIN=${SUBDOMAIN_LIST[IDX]};

    DATA=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=A&name=$SUBDOMAIN.$DOMAIN&page=1&per_page=20&order=type&direction=desc&match=all" \
         -H "X-Auth-Email: $EMAIL" \
         -H "Authorization: Bearer $API_KEY" \
         -H "Content-Type: application/json");

    DNS_ID=$(echo $DATA | jq -r ".result[].id");
    OLD_IP=$(echo $DATA | jq -r ".result[].content");

    DT=$(date "+%Y-%m-%d %H:%M:%S");

    if [ $NEW_IP != $OLD_IP ]; then
        echo "Old IP: $OLD_IP"
        echo "New IP: $NEW_IP"

        SUCCESS=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$DNS_ID" \
             -H "X-Auth-Email: $EMAIL" \
             -H "Authorization: Bearer $API_KEY" \
             -H "Content-Type: application/json" \
             --data "{\"type\":\"A\",\"name\":\"$SUBDOMAIN.$DOMAIN\",\"content\":\"$NEW_IP\"}" | jq -r ".success")
        echo "$DT: Successfully updated $SUBDOMAIN: $SUCCESS"
    else
        #echo "Same IP for $SUBDOMAIN: $NEW_IP"
        true
    fi

    IDX=$(( $IDX + 1 ));
done
