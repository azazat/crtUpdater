Problem: acme.sh cant autoupdate certificates due to old openssl, 
        it updates only manually via dns verify

Used tools:
        cobra + viper + acme.sh

Config file example:

        deadline: {{ days before expire }}
        mkr_host: {{ router IP }}
        mkr_user: {{ router user }}
        mkr_comment: {{ router rule comment }}
        domains:
        - {{ first domain }}
        - {{ second domain }}
        - {{ third domain }}
        *etc...
        httpport: {{ port on zimbra server to listen to for letsencrypt verify }}
        logfile: {{ path to logfile }}

        *we get first domain name as folder name where certificates are generated
