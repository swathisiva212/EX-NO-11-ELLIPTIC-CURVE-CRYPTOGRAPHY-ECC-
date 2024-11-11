# EX-NO-11-ELLIPTIC-CURVE-CRYPTOGRAPHY-ECC

## Aim:
To Implement ELLIPTIC CURVE CRYPTOGRAPHY(ECC)


## ALGORITHM:

1. Elliptic Curve Cryptography (ECC) is a public-key cryptography technique based on the algebraic structure of elliptic curves over finite fields.

2. Initialization:
   - Select an elliptic curve equation \( y^2 = x^3 + ax + b \) with parameters \( a \) and \( b \), along with a large prime \( p \) (defining the finite field).
   - Choose a base point \( G \) on the curve, which will be used for generating public keys.

3. Key Generation:
   - Each party selects a private key \( d \) (a random integer).
   - Calculate the public key as \( Q = d \times G \) (using elliptic curve point multiplication).

4. Encryption and Decryption:
   - Encryption: The sender uses the recipient’s public key and the base point \( G \) to encode the message.
   - Decryption: The recipient uses their private key to decode the message and retrieve the original plaintext.

5. Security: ECC’s security relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP), making it highly secure with shorter key lengths compared to traditional methods like RSA.

## Program:
```
#include <stdio.h>

// Define a structure to represent points on the elliptic curve
typedef struct {
    long long x, y;
} Point;

// Function to compute modular inverse (using Extended Euclidean Algorithm)
long long mod_inverse(long long a, long long p) {
    long long t = 0, new_t = 1;
    long long r = p, new_r = a;
    
    while (new_r != 0) {
        long long quotient = r / new_r;
        long long temp = t;
        t = new_t;
        new_t = temp - quotient * new_t;
        
        temp = r;
        r = new_r;
        new_r = temp - quotient * new_r;
    }
    
    if (r > 1) return -1;  // No inverse exists
    if (t < 0) t += p;
    
    return t;
}

// Function to perform point addition on elliptic curve
Point add_points(Point P, Point Q, long long a, long long p) {
    Point R;
    if (P.x == Q.x && P.y == Q.y) {
        // Case of P = Q (Point Doubling)
        long long m = (3 * P.x * P.x + a) * mod_inverse(2 * P.y, p) % p;
        R.x = (m * m - 2 * P.x) % p;
        R.y = (m * (P.x - R.x) - P.y) % p;
    } else {
        // Ordinary case
        long long m = (Q.y - P.y) * mod_inverse(Q.x - P.x, p) % p;
        R.x = (m * m - P.x - Q.x) % p;
        R.y = (m * (P.x - R.x) - P.y) % p;
    }

    // Ensure positive values
    if (R.x < 0) R.x += p;
    if (R.y < 0) R.y += p;

    return R;
}

// Function to perform scalar multiplication (Elliptic Curve Point Multiplication)
Point scalar_multiplication(Point P, long long k, long long a, long long p) {
    Point result = {0, 0}; // Point at infinity (neutral element)
    Point base = P;

    while (k > 0) {
        if (k % 2 == 1) {  // If k is odd, add base point
            result = add_points(result, base, a, p);
        }
        base = add_points(base, base, a, p);  // Double the point
        k /= 2;
    }
    return result;
}

int main() {
    long long p, a, b;
    Point G;
    long long alice_private_key, bob_private_key;
    Point alice_public_key, bob_public_key, alice_shared_secret, bob_shared_secret;

    // Input values
    printf("Enter the prime number (p): ");
    scanf("%lld", &p);
    printf("Enter the curve parameters (a and b) for equation y^2 = x^3 + ax + b: ");
    scanf("%lld %lld", &a, &b);
    printf("Enter the base point G (x and y): ");
    scanf("%lld %lld", &G.x, &G.y);
    printf("Enter Alice's private key: ");
    scanf("%lld", &alice_private_key);
    printf("Enter Bob's private key: ");
    scanf("%lld", &bob_private_key);

    // Compute public keys
    alice_public_key = scalar_multiplication(G, alice_private_key, a, p);
    bob_public_key = scalar_multiplication(G, bob_private_key, a, p);

    printf("Alice's public key: (%lld, %lld)\n", alice_public_key.x, alice_public_key.y);
    printf("Bob's public key: (%lld, %lld)\n", bob_public_key.x, bob_public_key.y);

    // Compute shared secrets
    alice_shared_secret = scalar_multiplication(bob_public_key, alice_private_key, a, p);
    bob_shared_secret = scalar_multiplication(alice_public_key, bob_private_key, a, p);

    printf("Shared secret computed by Alice: (%lld, %lld)\n", alice_shared_secret.x, alice_shared_secret.y);
    printf("Shared secret computed by Bob: (%lld, %lld)\n", bob_shared_secret.x, bob_shared_secret.y);

    // Verify if shared secrets match
    if (alice_shared_secret.x == bob_shared_secret.x && alice_shared_secret.y == bob_shared_secret.y) {
        printf("Key exchange successful. Shared secrets match.\n");
    } else {
        printf("Key exchange failed. Shared secrets do not match.\n");
    }

    return 0;
}
```


## Output:

![image](https://github.com/user-attachments/assets/1a7b2022-ba71-43ec-873b-a93dc90ce454)


## Result:
The program is executed successfully

