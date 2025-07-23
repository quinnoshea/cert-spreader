#!/bin/bash
#
# Define config
#
declare -a HOST=("azrael" "ftp" "odroid-m1" "riddler" "tautulli" "calibre-web" "joker" "alfred" "qbittorrent" "dns01" "dns02")
TF_VAR_proxmox01_url=https://proxmox01.batkave.net:8006
TF_VAR_proxmox02_url=https://proxmox02.batkave.net:8006
TF_VAR_proxmox_user='endfro@pve!letsencrypt'
TF_VAR_proxmox_token='e0c4a89d-5fc9-4788-9b7a-0d2c7985ad95'
cat_of_privkey=$(</etc/letsencrypt/live/batkave.net/privkey.pem)
cat_of_fullchain=$(</etc/letsencrypt/live/batkave.net/fullchain.pem)

# end of config

# Create a cert for Plex
/usr/bin/openssl pkcs12 -export -out /etc/letsencrypt/live/batkave.net/plex-certificate.pfx \
  -inkey /etc/letsencrypt/live/batkave.net/privkey.pem \
  -in /etc/letsencrypt/live/batkave.net/cert.pem \
  -certfile /etc/letsencrypt/live/batkave.net/fullchain.pem \
  -passout pass:Password1! 2>&1  | /usr/bin/logger -t rsync-push
chmod 755 /etc/letsencrypt/live/batkave.net/plex-certificate.pfx

# Reload local nginx to accept new cert
/usr/bin/systemctl reload nginx 2>&1 | /usr/bin/logger -t rsync-push

# Backup copies of certs and nginx
/usr/bin/rsync -pEvaLu -e /usr/bin/ssh /etc/letsencrypt/live/batkave.net/. joker.batkave.net:/mnt/nfs/data/sshkeys/ssl/. 2>&1 | /usr/bin/logger -t rsync-push
/usr/bin/rsync -pEvaLu --exclude 'modules/*' -e /usr/bin/ssh /etc/nginx/. joker.batkave.net:/mnt/nfs/data/sshkeys/nginx-configs/. 2>&1 | /usr/bin/logger -t rsync-push

# Push cert to hosts
for i in "${HOST[@]}"
        do
        /usr/bin/rsync -pEvaLu -e /usr/bin/ssh /etc/letsencrypt/live/batkave.net/. $i.batkave.net:/etc/letsencrypt/live/batkave.net/.  2>&1 | /usr/bin/logger -t rsync-push
done

# Push to alfred using unique ssh port
/usr/bin/rsync -pEvaLu -e '/usr/bin/ssh -p 42022' /etc/letsencrypt/live/batkave.net/. alfred.batkave.net:/etc/letsencrypt/live/batkave.net/. 2>&1 | /usr/bin/logger -t rsync-push

# Reload / Restart necessary services to use new cert
/usr/bin/ssh root@odroid-m1.batkave.net '/usr/bin/systemctl reload postfix dovecot nginx' 2>&1 | /usr/bin/logger -t rsync-push
/usr/bin/ssh root@riddler.batkave.net '/usr/bin/systemctl reload nginx' 2>&1 | /usr/bin/logger -t rsync-push
/usr/bin/ssh root@joker.batkave.net '/usr/bin/systemctl reload nginx && chown plex:plex /mnt/tank/data/sshkeys/ssl/plex-certificate.pfx' 2>&1 | /usr/bin/logger -t rsync-push
/usr/bin/ssh root@azrael.batkave.net '/usr/bin/systemctl restart plexmediaserver.service' 2>&1 | /usr/bin/logger -t rsync-push
/usr/bin/ssh -p 42022 root@alfred.batkave.net '/usr/bin/systemctl reload znc' 2>&1 | /usr/bin/logger -t rsync-push
/usr/bin/ssh root@dns01.batkave.net '/usr/bin/systemctl restart dns.service' 2>&1 | /usr/bin/logger -t rsync-push
/usr/bin/ssh root@dns02.batkave.net '/usr/bin/systemctl restart dns.service' 2>&1 | /usr/bin/logger -t rsync-push
/usr/bin/ssh root@calibre-web.batkave.net '/usr/bin/systemctl restart cps.service' 2>&1 | /usr/bin/logger -t rsync-push
/usr/bin/ssh root@ftp.batkave.net '/usr/bin/systemctl reload sftpgo.service' 2>&1 | /usr/bin/logger -t rsync-push
/usr/bin/ssh root@tautulli.batkave.net '/usr/bin/systemctl restart tautulli.service' 2>&1 | /usr/bin/logger -t rsync-push

# Send certs to proxmox, one host is generally offline on purpose
curl --connect-timeout 30 -v -k -X POST ${TF_VAR_proxmox02_url}/api2/json/nodes/proxmox02/certificates/custom \
        -H "Authorization: PVEAPIToken=${TF_VAR_proxmox_user}=${TF_VAR_proxmox_token}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "key=${cat_of_privkey}" \
        --data-urlencode "restart=1" \
        --data-urlencode "force=1" \
        --data-urlencode "node=proxmox02" \
        --data-urlencode "certificates=${cat_of_fullchain}" \
        2>&1 | /usr/bin/logger -t rsync-push

curl --connect-timeout 30 -v -k -X POST ${TF_VAR_proxmox01_url}/api2/json/nodes/proxmox01/certificates/custom \
        -H "Authorization: PVEAPIToken=${TF_VAR_proxmox_user}=${TF_VAR_proxmox_token}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "key=${cat_of_privkey}" \
        --data-urlencode "restart=1" \
        --data-urlencode "force=1" \
        --data-urlencode "node=proxmox01" \
        --data-urlencode "certificates=${cat_of_fullchain}" \
        2>&1 | /usr/bin/logger -t rsync-push
