// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_bfv_basics()
{
    print_example_banner("Example: BFV Basics");

    EncryptionParameters parms(scheme_type::BFV);

    /*

    Larger poly_modulus_degree makes ciphertext sizes larger and all operations
    slower, but enables more complicated encrypted computations. Recommended
    values are 1024, 2048, 4096, 8192, 16384, 32768, but it is also possible
    to go beyond this range.
    */
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    /*
    The plaintext modulus can be any positive integer, even though here we take
    it to be a power of two. In fact, in many cases one might instead want it
    to be a prime number; we will see this in later examples. The plaintext
    modulus determines the size of the plaintext data type and the consumption
    of noise budget in multiplications. The noise budget in a freshly encrypted ciphertext is
     ~ log2(coeff_modulus/plain_modulus) (bits)
    and the noise budget consumption in a homomorphic multiplication is of the
    form log2(plain_modulus) + (other terms).
    The plaintext modulus is specific to the BFV scheme, and cannot be set when
    using the CKKS scheme.
    */
    parms.set_plain_modulus(256);

    /*
    Now that all parameters are set, we are ready to construct a SEALContext
    object. This is a heavy class that checks the validity and properties of the
    parameters we just set.
    */
    auto context = SEALContext::Create(parms);

    /*
    Print the parameters that we have chosen.
    */
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    cout << endl;
    cout << "~~~~~~ A naive way to calculate 2(x^2+1)(x+1)^2. ~~~~~~" << endl;

   
    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
   
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);

    /*
    As an example, we evaluate the degree 4 polynomial

        2x^4 + 4x^3 + 4x^2 + 4x + 2

    over an encrypted x = 6. The coefficients of the polynomial can be considered
    as plaintext inputs, as we will see below. The computation is done modulo the
    plain_modulus 256.

    While this examples is simple and easy to understand, it does not have much
    practical value. In later examples we will demonstrate how to compute more
    efficiently on encrypted integers and real or complex numbers.
    */
    print_line(__LINE__);
    int x = 6;
    Plaintext x_plain(to_string(x));
    cout << "Express x = " + to_string(x) +
        " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;

    /*
    We then encrypt the plaintext, producing a ciphertext.
    */
    print_line(__LINE__);
    Ciphertext x_encrypted;
    cout << "Encrypt x_plain to x_encrypted." << endl;
    encryptor.encrypt(x_plain, x_encrypted);

    /*
    In Microsoft SEAL, a valid ciphertext consists of two or more polynomials
    whose coefficients are integers modulo the product of the primes in the
    coeff_modulus. The number of polynomials in a ciphertext is called its `size'
    and is given by Ciphertext::size(). A freshly encrypted ciphertext always
    has size 2.
    */
    cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;

    /*
    There is plenty of noise budget left in this freshly encrypted ciphertext.
    */
    cout << "    + noise budget in freshly encrypted x: "
        << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;

    /*
    We decrypt the ciphertext and print the resulting plaintext in order to
    demonstrate correctness of the encryption.
    */
    Plaintext x_decrypted;
    cout << "    + decryption of x_encrypted: ";
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;

    /*
    When using Microsoft SEAL, it is typically advantageous to compute in a way
    that minimizes the longest chain of sequential multiplications. In other
    words, encrypted computations are best evaluated in a way that minimizes
    the multiplicative depth of the computation, because the total noise budget
    consumption is proportional to the multiplicative depth. For example, for
    our example computation it is advantageous to factorize the polynomial as

        2x^4 + 4x^3 + 4x^2 + 4x + 2 = 2(x + 1)^2 * (x^2 + 1)

    to obtain a simple depth 2 representation. Thus, we compute (x + 1)^2 and
    (x^2 + 1) separately, before multiplying them, and multiplying by 2.

    First, we compute x^2 and add a plaintext "1". We can clearly see from the
    print-out that multiplication has consumed a lot of noise budget. The user
    can vary the plain_modulus parameter to see its effect on the rate of noise
    budget consumption.
    */
    print_line(__LINE__);
    cout << "Compute x_sq_plus_one (x^2+1)." << endl;
    Ciphertext x_sq_plus_one;
    evaluator.square(x_encrypted, x_sq_plus_one);
    Plaintext plain_one("1");
    evaluator.add_plain_inplace(x_sq_plus_one, plain_one);

    /*
    Encrypted multiplication results in the output ciphertext growing in size.
    More precisely, if the input ciphertexts have size M and N, then the output
    ciphertext after homomorphic multiplication will have size M+N-1. In this
    case we perform a squaring, and observe both size growth and noise budget
    consumption.
    */
    cout << "    + size of x_sq_plus_one: " << x_sq_plus_one.size() << endl;
    cout << "    + noise budget in x_sq_plus_one: "
        << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;

    /*
    Even though the size has grown, decryption works as usual as long as noise
    budget has not reached 0.
    */
    Plaintext decrypted_result;
    cout << "    + decryption of x_sq_plus_one: ";
    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

    /*
    Next, we compute (x + 1)^2.
    */
    print_line(__LINE__);
    cout << "Compute x_plus_one_sq ((x+1)^2)." << endl;
    Ciphertext x_plus_one_sq;
    evaluator.add_plain(x_encrypted, plain_one, x_plus_one_sq);
    evaluator.square_inplace(x_plus_one_sq);
    cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
    cout << "    + noise budget in x_plus_one_sq: "
        << decryptor.invariant_noise_budget(x_plus_one_sq)
        << " bits" << endl;
    cout << "    + decryption of x_plus_one_sq: ";
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

    cout << "Compute encrypted_result (2(x^2+1)(x+1)^2)." << endl;
    Ciphertext encrypted_result;
    Plaintext plain_two("2");
    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_two);
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
  
    cout << "~~~~~~ A better way to calculate 2(x^2+1)(x+1)^2. ~~~~~~" << endl;

    /*
    Noise budget has reached 0, which means that decryption cannot be expected
    to give the correct result. This is because both ciphertexts x_sq_plus_one
    and x_plus_one_sq consist of 3 polynomials due to the previous squaring
    operations, and homomorphic operations on large ciphertexts consume much more
    noise budget than computations on small ciphertexts. Computing on smaller
    ciphertexts is also computationally significantly cheaper.

    `Relinearization' is an operation that reduces the size of a ciphertext after
    multiplication back to the initial size, 2. Thus, relinearizing one or both
    input ciphertexts before the next multiplication can have a huge positive
    impact on both noise growth and performance, even though relinearization has
    a significant computational cost itself. It is only possible to relinearize
    size 3 ciphertexts down to size 2, so often the user would want to relinearize
    after each multiplication to keep the ciphertext sizes at 2.

    Relinearization requires special `relinearization keys', which can be thought
    of as a kind of public key. Relinearization keys can easily be created with
    the KeyGenerator.

    Relinearization is used similarly in both the BFV and the CKKS schemes, but
    in this example we continue using BFV. We repeat our computation from before,
    but this time relinearize after every multiplication.

    We use KeyGenerator::relin_keys() to create relinearization keys.
    */
    print_line(__LINE__);
    cout << "Generate relinearization keys." << endl;
    auto relin_keys = keygen.relin_keys();

    /*
    We now repeat the computation relinearizing after each multiplication.
    */
    print_line(__LINE__);
    cout << "Compute and relinearize x_squared (x^2)," << endl;
    cout << string(13, ' ') << "then compute x_sq_plus_one (x^2+1)" << endl;
    Ciphertext x_squared;
    evaluator.square(x_encrypted, x_squared);
    cout << "    + size of x_squared: " << x_squared.size() << endl;
    evaluator.relinearize_inplace(x_squared, relin_keys);
    cout << "    + size of x_squared (after relinearization): "
        << x_squared.size() << endl;
    evaluator.add_plain(x_squared, plain_one, x_sq_plus_one);
    cout << "    + noise budget in x_sq_plus_one: "
        << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;
    cout << "    + decryption of x_sq_plus_one: ";
    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

    print_line(__LINE__);
    Ciphertext x_plus_one;
    cout << "Compute x_plus_one (x+1)," << endl;
    cout << string(13, ' ')
        << "then compute and relinearize x_plus_one_sq ((x+1)^2)." << endl;
    evaluator.add_plain(x_encrypted, plain_one, x_plus_one);
    evaluator.square(x_plus_one, x_plus_one_sq);
    cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
    evaluator.relinearize_inplace(x_plus_one_sq, relin_keys);
    cout << "    + noise budget in x_plus_one_sq: "
        << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits" << endl;
    cout << "    + decryption of x_plus_one_sq: ";
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

    print_line(__LINE__);
    cout << "Compute and relinearize encrypted_result (2(x^2+1)(x+1)^2)." << endl;
    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_two);
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
    cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    cout << "    + size of encrypted_result (after relinearization): "
        << encrypted_result.size() << endl;
    cout << "    + noise budget in encrypted_result: "
        << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;

    cout << endl;
    cout << "NOTE: Notice the increase in remaining noise budget." << endl;

    /*
    Relinearization clearly improved our noise consumption. We have still plenty
    of noise budget left, so we can expect the correct answer when decrypting.
    */
    print_line(__LINE__);
    cout << "Decrypt encrypted_result (2(x^2+1)(x+1)^2)." << endl;
    decryptor.decrypt(encrypted_result, decrypted_result);
    cout << "    + decryption of 2(x^2+1)(x+1)^2 = 0x"
        << decrypted_result.to_string() << " ...... Correct." << endl;
    cout << endl;

    /*
    For x=6, 2(x^2+1)(x+1)^2 = 3626. Since the plaintext modulus is set to 256,
    this result is computed in integers modulo 256. Therefore the expected output
    should be 3626 % 256 == 42, or 0x2A in hexadecimal.
    */
}
