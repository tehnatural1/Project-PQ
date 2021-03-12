"""
This is an extremely simplified and paired down version a quadratic sieve. If
you come across a faster way to identify a prime or find the next prime number
after a given number please feel free to email it to me dholl086@uottawa.ca

Module Use Case Example:
    Finding the next prime number of a simple 2048 bit integer (617 digits):
        >>> initial_number = (0b1 << 2047)          # 0b1000_0000_ .... _0000
        >>> Prime.next_prime(initial_number)

"""

# Limit importing to the Prime class
__all__         =   [ "Prime" ]

# Primes less than 212 - this array is used to speed up the identification of
# large prime numbers by checking if each is a factor of the large number.
SMALL_PRIMES    =   [
                          2,   3,   5,   7, 11,   13,  17,  19,  23,  29,
                         31,  37,  41,  43, 47,   53,  59,  61,  67,  71,
                         73,  79,  83,  89, 97,  101, 103, 107, 109, 113,
                        127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
                        179, 181, 191, 193, 197, 199, 211
                    ]

# Pre-calculated sieve of eratosthenes for n = 2, 3, 5, 7
# NOTE: Must be ordered
SIEVE_INDICES   =   [
                          1,  11,  13,  17,  19,  23,  29,  31,  37,  41,
                         43,  47,  53,  59,  61,  67,  71,  73,  79,  83,
                         89,  97, 101, 103, 107, 109, 113, 121, 127, 131,
                        137, 139, 143, 149, 151, 157, 163, 167, 169, 173,
                        179, 181, 187, 191, 193, 197, 199, 209
                    ]

# Distances between sieve values of the SIEVE_INDICES array above
# For example:
#   Index 0 and 1 array element distance 1 and 11 ==> 10
#   Index 1 and 2 array element distance 11 and 13 ==> 2 ...
SIEVE_OFFSETS   =   [
                         10, 2, 4, 2, 4, 6, 2, 6, 4, 2, 4, 6,
                          6, 2, 6, 4, 2, 6, 4, 6, 8, 4, 2, 4,
                          2, 4, 8, 6, 4, 6, 2, 4, 6, 2, 6, 6,
                          4, 2, 4, 6, 2, 6, 4, 2, 4, 2,10, 2
                    ]

# Maximum 32 bit integer value
MAX_INT         =   2_147_483_647


def binary_search(a:list, x:int) -> int:
    """
    Find the index of an element in a sorted list.

    Args:
        a (list): Sorted list to compare x against.
        x (int): Element to run search against on the list.

    Returns:
        (int) Specifying the index of the element if the element is present in
            the list, otherwise the index of the next largest element.

    """
    s = 0
    e = len(a)
    m = e >> 1
    while m != e:
        if a[m] < x:
            s = m
            m = (s + e + 1) >> 1
        else:
            e = m
            m = (s + e) >> 1
    return m


class Prime:
    """
    Container class for prime number methods
    """

    @staticmethod
    def legendre_symbol(a:int, m:int) -> int:
        """
        Legendre symbol (a|m)

        NOTE: returns (m - 1) if `a` is a non-residue instead of -1

        Returns:
            (int) representation of the legendre symbol

        """
        return pow(a, (m-1) >> 1, m)

    @staticmethod
    def is_probable_prime(n:int, b:int=2):
        """
        Probabilistic priminality check for a given integer.

        Args:
            n (int): The number to check.
            b (int): Base number to generate checks against.

        Returns:
            (bool) indicating if the number is a probable prime.

        """
        if (n < 2): return False
        d = n - 1
        s = 0

        # Shift bits until the first bit is not set (and count the shifts).
        while (d & 1 == 0):
            s += 1
            d >>= 1

        # Check for non-residue
        x = pow(b, d, n)
        if ((x == 1) or (x == (n -1))): return True

        # Scale x by the amount of shifts
        for _ in range(1, s):
            x = (x * x) % n

            if   (x == 1):      return False
            elif (x == (n -1)): return True

        return False


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
        # Check if n is 2-sqrp and 3-sqrp to ensure n is square free
        if not Prime.is_probable_prime(n, 2): return False
        if not Prime.is_probable_prime(n, 3): return False

        a = 5
        s = 2

        # NOTE: If n is a perfect square this test will run forever. This is
        #   mitigated by the probable prime checks above.
        while (Prime.legendre_symbol(a, n) != (n -1)):
            s = -s
            a = s - a

        return Prime.lucas_primality_test(n, a)


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
        Q = (1 - D) >> 2

        # n+1 = 2**r*s where s is odd
        s = (n + 1)
        r = 0
        while (s & 1 == 0):
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
            if (t & 1):
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


    @staticmethod
    def is_prime(n:int) -> bool:
        """
        Probability check if a number is prime.

        Args:
            n (int): Specifies the number to check.

        Returns:
            (bool) Indicating whether or not the number is a probable prime.

        """
        # Trivial case where n must be in the predifined prime list
        if (n < 212):
            return ( n == SMALL_PRIMES[ binary_search(SMALL_PRIMES, n) ] )

        # Check if n can be factored by any of the small primes
        for p in SMALL_PRIMES:
            if ((n % p) == 0): return False

        # Attempt trial division if n is a 32bit integer
        if (n <= MAX_INT):
            p = 211
            while ((p * p) < n):
                for o in SIEVE_OFFSETS:
                    p += o
                    if ((n % p) == 0): return False

            return True

        return Prime.baillie_psw_primality_test(n)

    @staticmethod
    def next_prime(n:int) -> int:
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
        # Simple case where n is 1
        if (n < 2): return 2

        n += 1

        # Circumstance where n is in the predifined list of primes
        if (n < 212):
            return SMALL_PRIMES[ binary_search(SMALL_PRIMES, n) ]

        # Scale n to the largest predifined index
        x = int(n % 210)

        # Find the closest match to the scaled value in the indices
        m = binary_search(SIEVE_INDICES, x)

        # Generate a candidate prime number
        i = int(n + (SIEVE_INDICES[m] - x))

        # Enable offset rotation by placing offsets before the mid to the end
        rotated_offsets = SIEVE_OFFSETS[m:] + SIEVE_OFFSETS[:m]

        # Run until a prime number is found
        while True:
            for o in rotated_offsets:
                if Prime.is_prime(i): return i
                i += o
