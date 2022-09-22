/**
 * @file ecdsa_main.c
 * @details It uses OPENSSL library for Elliptic Curve functions. Suggested package to be used in ubuntu : libssl-dev
 * @version 1.0
 * @date 2021-01-04
 */

#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <string.h>

#define SUCCESS 1
#define FAILURE 0

#define HASH_LEN 33

int run_ecdsa_demo(unsigned char *hash, unsigned int hash_len)
{
    int status;

    /** Initialize EC Key **/
    EC_KEY *ec_key = EC_KEY_new();
    if (ec_key == NULL)
    {
        printf("\nERROR!! Failed to initialize new EC Key");
        return FAILURE;
    }

    /** Initialize EC Group **/
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_secp192k1);
    if (ec_group == NULL)
    {
        printf("\nERROR!! Failed to initialize new EC Group");
        return FAILURE;
    }

    /** Set group in EC Key **/
    status = EC_KEY_set_group(ec_key, ec_group);
    if (status != SUCCESS)
    {
        printf("\nERROR!! Failed to set group for EC Key");
        return FAILURE;
    }

    /** Generate Key **/
    status = EC_KEY_generate_key(ec_key);
    if (status != SUCCESS)
    {
        printf("\nERROR!! Failed to generate EC Key");
        return FAILURE;
    }

    printf("\n**LOG: Generating EC Key & Group Success");

    /** Sign Message hash using key **/
    ECDSA_SIG *signature = ECDSA_do_sign(hash, strlen(hash), ec_key);
    if (signature == NULL)
    {
        printf("\nERRORFailed to generate EC Signature\n");
        return FAILURE;
    }

    printf("\n**LOG: ECDSA Sign Success");
    /** Verify Signature **/
    status = ECDSA_do_verify(hash, hash_len, signature, ec_key);
    if (status != SUCCESS)
    {
        printf("\nERROR!! Failed to verify EC Signature");
        return FAILURE;
    }
    printf("\n**LOG: ECDSA Verify Success");

    /** Alter Message hash **/
    printf("\n**LOG: Altering message hash");
    hash[0] = '8';

    /** Run Verification **/
    status = ECDSA_do_verify(hash, hash_len, signature, ec_key);
    if (status == SUCCESS)
    {
        printf("\nERROR!! Failed to reject EC Signature");
        return FAILURE;
    }

    printf("\n**LOG: ECDSA Reject Success");
    /** Free key and group memory **/
    EC_GROUP_free(ec_group);
    EC_KEY_free(ec_key);
    return SUCCESS;
}

int main(int argc, char *argv[])
{
    printf("\n**LOG: Starting ECDSA Demo using OPENSSL library");
    unsigned char hash[HASH_LEN] = "4fb6d00155963f1817cd4e432375dc81";
    int status = run_ecdsa_demo(hash, HASH_LEN);
    printf("\n**LOG: Demo return %s\n", status ? "Success" : "Failure");
    return (0);
}