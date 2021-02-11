time sqlite3 ./databases/$1.db "SELECT COUNT( DISTINCT( public_key ) ) FROM publicKeys;"; alert
