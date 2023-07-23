/ip firewall layer7-protocol
add name="Torrent sites" regexp="^.+(torrent|rarbg|thepiratebay|isohunts|enter\
    tane|demonoid|btjunkie|mininova|flixflux|torrentz|vertor|h33t|btscene|bitu\
    nity|bittoxic|thunderbytes|entertane|zoozle|vcdq|bitnova|bitsoup|meganova|\
    fulldls|btbot|flixflux|seedpeer|fenopy|gpirate|commonbits|d1:ad2|tracker|a\
    nnounce).*\$"
add comment="Block Torrents" name=block-torrents regexp="^(\\x13bittorrent pro\
    tocol|azver\\x01\$|get /scrape\\\?info_hash=get /announce\\\?info_hash=|ge\
    t /client/bitcomet/|GET /data\\\?fid=)|d1:ad2:id20:|\\x08'7P\\)[RP]"

/ip firewall filter
add action=add-src-to-address-list address-list=Torrent-Conn \
    address-list-timeout=2m chain=forward comment="Torrent Block 1/4" \
    layer7-protocol=block-torrents src-address=192.168.2.0/24 \
    src-address-list=!allow-bit
# p2p matcher is obsolete please use layer7 matcher instead
add action=add-src-to-address-list address-list=Torrent-Conn \
    address-list-timeout=2m chain=forward comment="Torrent Block 2/4" p2p=\
    all-p2p src-address=192.168.2.0/24 src-address-list=!allow-bit
add action=drop chain=forward comment="Torrent Block 3/4" dst-port=\
    !0-1024,8291,5900,5800,3389,14147,5222,59905 protocol=tcp \
    src-address-list=Torrent-Conn
add action=drop chain=forward comment="Torrent Block 4/4" dst-port=\
    !0-1024,8291,5900,5800,3389,14147,5222,59905 protocol=udp \
    src-address-list=Torrent-Conn