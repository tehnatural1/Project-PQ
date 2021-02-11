time sqlite3 ./databases/$1.db "SELECT encryption, count(encryption) AS occurence FROM publicKeys GROUP BY encryption ORDER BY occurence;"; alert
