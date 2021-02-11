time sqlite3 ./databases/$1.db "SELECT public_key, count(public_key) AS occurence FROM publicKeys GROUP BY public_key ORDER BY occurence DESC LIMIT 10;"; alert
