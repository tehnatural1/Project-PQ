"""
This is an extremely simplified and paired down version a quadratic sieve. If
you come across a faster way to identify a prime or find the next prime number
after a given number please feel free to email it to me dholl086@uottawa.ca

NOTE:
    The code of this method assumes numbers being checked are larger than 212 in
    size. This is a limitation presented from the simplication of a quadratic
    sieve. Since the small primes (less than 212) are easy to find, I did not
    care to add support for them.

"""

# Pre-calculated sieve of eratosthenes for n = 2, 3, 5, 7
INDICES         =   [
                          1,  11,  13,  17,  19,  23,  29,  31,  37,  41,
                         43,  47,  53,  59,  61,  67,  71,  73,  79,  83,
                         89,  97, 101, 103, 107, 109, 113, 121, 127, 131,
                        137, 139, 143, 149, 151, 157, 163, 167, 169, 173,
                        179, 181, 187, 191, 193, 197, 199, 209
                    ]

# Distances between sieve values
OFFSETS         =   [
                         10, 2, 4, 2, 4, 6, 2, 6, 4, 2, 4, 6,
                          6, 2, 6, 4, 2, 6, 4, 6, 8, 4, 2, 4,
                          2, 4, 8, 6, 4, 6, 2, 4, 6, 2, 6, 6,
                          4, 2, 4, 6, 2, 6, 4, 2, 4, 2,10, 2
                    ]

MAX_INT         =   2147483647



class Prime:
    """
    Container class for prime number methods
    """

    @staticmethod
    def legendre_symbol(a:int, m:int) -> int:
        """
        Legendre symbol (a|m)

        NOTE: returns (m - 1) if a is a non-residue instead of -1

        Returns:
            (int) representation of the legendre symbol

        """
        return pow(a, (m-1) >> 1, m)

    @staticmethod
    def baillie_psw_primality_test(n:int, b:int=2) -> bool:
        """
        Checks if a given number using the Baillie–PSW primality test.

        Args:
            n (int): The number to check.
            b (int): The base number an exponent will be raised against.

        Returns:
            (bool) whether or not the number has probability to be prime.

        """
        d = n - 1
        s = 0

        while ((d & 1) == 0):
            s += 1
            d >>= 1

        x = pow(b, d, n)
        if ((x == 1) or (x == (n - 1))): return True

        for _ in range(1, s):
            x = ((x * x) % n)
            if   (x == 1):       return False
            elif (x == (n - 1)): return True

        return False

    @staticmethod
    def lucas_primality_test(n:int, D:int) -> bool:
        """
        Checks if a given number using the Lucas primality test.

        Args:
            n (int): The number to check.
            D (int): Determines the accuracy of the test.

        Returns:
            (bool) whether or not the number passes Lucas primality test.

        """
        Q = (1-D) >> 2

        # n+1 = 2**r*s where s is odd
        s = n+1
        r = 0
        while s&1 == 0:
            r += 1
            s >>= 1

        # Calculate the bit reversal of (odd) s, e.g. 19 (10011) <=> 25 (11001)
        t = 0
        while (s > 0):
            if (s & 1):
                t += 1
                s -= 1
            else:
                t <<= 1
                s >>= 1

        # Keeping track of q = Q**n
        U = 0
        V = 2
        q = 1

        # Use the same bit reversal process to calculate the sth Lucas number
        inv_2 = (n+1) >> 1
        while (t > 0):
            if ((t & 1) == 1):
                # U, V of n+1
                U, V = ((U + V) * inv_2)%n, ((D*U + V) * inv_2)%n
                q = (q * Q)%n
                t -= 1

            else:
                # U, V of n*2
                U, V = (U * V)%n, (V * V - 2 * q)%n
                q = (q * q)%n
                t >>= 1

        # Double s until the 2**r*sth Lucas number
        while (r > 0):
            U, V = (U * V)%n, (V * V - 2 * q)%n
            q = (q * q)%n
            r -= 1

        # If n is prime, n divides the n+1st Lucas number
        return (U == 0)


    # an 'almost certain' primality check
    @staticmethod
    def is_prime(n):
        """
        Probability check if a number is prime.

        Args:
            n (int): Specifies the number to check.

        Returns:
            (bool) Indicating whether or not the number is a probable prime.

        """
        # Perform full trial division on 32-bit integers
        if (n <= MAX_INT):
            i = 211
            while ((i * i) < n):
                for o in OFFSETS:
                    i += o
                    if ((n % i) == 0): return False

            return True

        # Check the number with Baillie-PSW primality test
        if not Prime.baillie_psw_primality_test(n): return False

        a = 5
        s = 2

        while (Prime.legendre_symbol(a, n) != (n - 1)):
            s = -s
            a = s-a

        return Prime.lucas_primality_test(n, a)

    @staticmethod
    def next_prime(n:int, f:callable=Prime.increment) -> int:
        """
        Obtain the next prime number that is either smaller than or greater than
        a given number.

        Args:
            n (int): Specifies the number to find prime numbers surrounding.
            f (callable): Specifies which method to use, which in turn defines
                if the prime will be smaller or greater than the number.

        Returns:
            (int) A prime number suiting the characteristics of the arguments.

        """
        # First odd larger than n
        n = (n + 1) | 1

        x = int(n % 210)
        s = 0
        e = 47
        m = 24

        # Binary search to find sieve rotation position
        while (m != e):
            if (INDICES[m] < x):
                s = m
                m = (s + e + 1) >> 1
            else:
                e = m
                m = (s + e) >> 1

        i = f(n,m,x)

        # Adjust offsets
        offs = OFFSETS[m:] + OFFSETS[:m]
        while True:
            for o in offs:
                if Prime.is_prime(i): return i
                i += o


    @staticmethod
    def increment(n:int, m:int, x:int) -> int:
        return int(n + (INDICES[m] - x))

    @staticmethod
    def decriment(n:int, m:int, x:int) -> int:
        return int(n - (INDICES[m] + x))

    @staticmethod
    def previous_prime(n:int) -> int:
        return Prime.next_prime(n, Prime.decriment)
