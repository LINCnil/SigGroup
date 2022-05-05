// BLS + BB signature with Schnorr proofs...
#include <string.h>

#include "pbc.h"

typedef int bool;
#define true 1
#define false 0

//-----------------------------------------------------------------------------
// Valeurs partagées
//-----------------------------------------------------------------------------
#define fileName "param.pbc"
#define unittest 0

void comp(bool b, char s[])
{
  printf("///====================================\\\\\\ \n");

  if (!b)
  {
    printf("         %s works\n", s);
  }
  else
  {
    printf("      %s does not work :()\n", s);
  }

  printf("\\\\\\====================================/// \n");
}

void setPairing(pairing_t pairing)
{
  FILE *pFile;
  long lSize;
  char *buffer;
  size_t result;
  pbc_param_t par;

  pFile = fopen(fileName, "r");
  if (pFile == NULL)
  {
    fputs("File error", stderr);
    exit(1);
  }
  fseek(pFile, 0, SEEK_END);
  lSize = ftell(pFile);
  rewind(pFile);
  buffer = (char *)malloc(sizeof(char) * lSize);
  if (buffer == NULL)
  {
    fputs("Memory error", stderr);
    exit(2);
  }
  result = fread(buffer, 1, lSize, pFile);
  if (result != lSize)
  {
    fputs("Reading error", stderr);
    exit(3);
  }
  pbc_param_init_set_str(par, buffer);
  pairing_init_pbc_param(pairing, par);
  pbc_param_clear(par);
  fclose(pFile);
  free(buffer);
}

//-----------------------------------------------------------------------------
// Code des autorités d'accréditations des autorités de certification
//-----------------------------------------------------------------------------
void authority_init(char *gsk_buffer_out, 
                    char *gpk_buffer_out, 
                    char *alpha_buffer_out,
                    char *g1_buffer_out,
                    char *g2_buffer_out)
{
  pairing_t pairing;
  setPairing(pairing);
  element_t g1, g2;
  element_init_G1(g1, pairing);
  element_init_G2(g2, pairing);

  // Groth Sahai:
  element_t g11, g12, h11, h12, g21, g22, h21, h22, dla, dlb;
  element_init_G1(g11, pairing);
  element_init_G1(g12, pairing);
  element_init_G1(h11, pairing);
  element_init_G1(h12, pairing);
  element_init_G2(g21, pairing);
  element_init_G2(g22, pairing);
  element_init_G2(h21, pairing);
  element_init_G2(h22, pairing);
  element_init_Zr(dla, pairing);
  element_init_Zr(dlb, pairing);

  // Soundness mode!  (No real reason to prefer one over the other, but less random call with this one... if preferred take all h random and disregard a,b)
  element_random(g11);
  element_random(g12);
  element_random(g21);
  element_random(g22);
  element_random(dla);
  element_random(dlb);
  element_pow_zn(h11, g11, dla);
  element_pow_zn(h12, g12, dla);
  element_pow_zn(h21, g21, dlb);
  element_pow_zn(h22, g22, dlb);

  // G1, G2 generators
  element_random(g1);
  element_random(g2);

  // Master key generation by the main authority
  // Things in 1 are in G1, things in 2 are in G2
  // Keygen param -> pk (elem G2), sk (elem Zp), RL : (elem list)
  element_t alpha, gsk, gpk;
  element_init_Zr(alpha, pairing);
  element_init_Zr(gsk, pairing);
    element_init_G2(gpk, pairing);

  element_random(alpha);
  element_random(gsk);

  element_mul_zn(gpk, g2, gsk);
  
  if (unittest)
  {
    element_printf("Public values: gpk : %B \n", gpk);
    element_printf("Secret values: gsk : %B, alpha : %B\n", gsk, alpha);
  }

  // Sending values
  element_to_bytes(gsk_buffer_out, gsk);
  element_to_bytes(gpk_buffer_out, gpk);
  element_to_bytes(alpha_buffer_out, alpha);
  element_to_bytes(g1_buffer_out, g1);
  element_to_bytes(g2_buffer_out, g2);

  if (unittest)
  {
    element_t temp1, t1, t2;
    element_init_G1(temp1, pairing);
    element_init_GT(t1, pairing);
    element_init_GT(t2, pairing);
    element_pow_zn(temp1, g1, gsk);
    pairing_apply(t1, temp1, g2, pairing);
    pairing_apply(t2, g1, gpk, pairing);

    comp(element_cmp(t1, t2), "KeyGen");
  }

  //Cleanup
  element_clear(g11);
  element_clear(g12);
  element_clear(h11);
  element_clear(h12);
  element_clear(g21);
  element_clear(g22);
  element_clear(h21);
  element_clear(h22);
  element_clear(dla);
  element_clear(dlb);
  element_clear(g1);
  element_clear(g2);
  pairing_clear(pairing);
}

void new_certificate(char *gsk_buffer_in,
                     char *gpk_buffer_in,
                     char *g1_buffer_in,
                     char *g2_buffer_in,
                     char *y_buffer_out,
                     char *cert_buffer_out,
                     char *tk_buffer_out)
{

  pairing_t pairing;
  setPairing(pairing);

  // Retrieve public and secret key from the autority
  element_t g1, g2;
  element_init_G1(g1, pairing);
  element_init_G2(g2, pairing);
  element_from_bytes(g1, g1_buffer_in);
  element_from_bytes(g2, g2_buffer_in);

  element_t gsk, gpk;
  element_init_Zr(gsk, pairing);
  element_from_bytes(gsk, gsk_buffer_in);
  element_init_G2(gpk, pairing);
  element_from_bytes(gpk, gpk_buffer_in);

  // Certification key generation by the main authority for the sub authority
  // y_0 could be chosen jointly... but bleh...
  // CertifKeyGen (param, sk Zp) -> yi (elem Zp), si (elem G1), tk (elem g2)
  element_t y, s, n, tk;
  element_init_Zr(y, pairing);
  element_init_Zr(n, pairing);
  element_init_G1(s, pairing);
  element_init_G2(tk, pairing);

  element_random(y);

  element_add(n, y, gsk);
  element_invert(n, n);
  element_pow_zn(s, g1, n);
  element_pow_zn(tk, g2, y);
  
  if (unittest)
  {
    element_printf("Certif is: y : %B, cert : %B, tk : %B\n", y, s, tk);
  }

  // Sending result
  element_to_bytes(y_buffer_out, y);
  element_to_bytes(cert_buffer_out, s);
  element_to_bytes(tk_buffer_out, tk);

  if (unittest)
  {
    element_t temp1, temp2, temp3;
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_G2(temp3, pairing);

    element_mul(temp3, tk, gpk);
    pairing_apply(temp1, g1, g2, pairing);
    pairing_apply(temp2, s, temp3, pairing);

    comp(element_cmp(temp1, temp2), "CertifKeyGen");
  }

   //Cleanup
  element_clear(g1);
  element_clear(g2);
  element_clear(gsk);
  element_clear(gpk);
  element_clear(y);
  element_clear(s);
  element_clear(n);
  element_clear(tk);
  pairing_clear(pairing);
}

//-----------------------------------------------------------------------------
// Code des sites vérificateurs
//-----------------------------------------------------------------------------

int site_verify_tk(
  char *chal_buffer_in,
  char *sig_buffer_in,
  char *g2_buffer_in,
  char *tk_buffer_in
){
  pairing_t pairing;
  setPairing(pairing);

  // Init elements from inputs
  element_t chal, tk, g2, sig;
  element_init_G1(chal, pairing);
  element_init_G2(g2, pairing);
  element_init_G1(sig, pairing);
  element_init_G2(tk, pairing);
  element_from_hash(chal, chal_buffer_in, strlen(chal_buffer_in));
  element_from_bytes(g2, g2_buffer_in);
  element_from_bytes(sig, sig_buffer_in);
  element_from_bytes(tk, tk_buffer_in);

  // First check is the signature comes from a revocated authority, normaly a list of tk but let's assume we only have one
  element_t temp1, temp2;
  element_init_GT(temp1, pairing);
  element_init_GT(temp2, pairing);
  pairing_apply(temp1, sig, g2, pairing);
  pairing_apply(temp2, chal, tk, pairing);
  int test1 = element_cmp(temp1, temp2);
  if (unittest)
  {
    comp(test1, "Revocation check");
  }

  element_clear(temp1);
  element_clear(temp2);
  element_clear(chal);
  element_clear(tk);
  element_clear(sig);
  element_clear(g2);
  pairing_clear(pairing);

  return !test1;
}

int site_verify_sign(
    char *chal_buffer_in,
    char *gpk_buffer_in,
    char *y_buffer_in,
    char *cert_buffer_in,
    char *g1_buffer_in,
    char *g2_buffer_in,
    char *sig_buffer_in,
    char *c1_buffer_in,
    char *c2_buffer_in,
    char *d1_buffer_in,
    char *d2_buffer_in,
    char *p1_buffer_in,
    char *p11_buffer_in,
    char *p12_buffer_in,
    char *p21_buffer_in,
    char *p22_buffer_in,
    char *th11_buffer_in,
    char *th12_buffer_in,
    char *th21_buffer_in,
    char *th22_buffer_in,
    char *g11_buffer_in,
    char *g12_buffer_in,
    char *h11_buffer_in,
    char *h12_buffer_in,
    char *g21_buffer_in,
    char *g22_buffer_in,
    char *h21_buffer_in,
    char *h22_buffer_in)
{
  // Résultat final du test
  int result = 1;

  pairing_t pairing;
  setPairing(pairing);

  // load elements
  element_t chal, y, s, gpk;
  element_init_G1(chal, pairing);
  element_from_hash(chal, chal_buffer_in, strlen(chal_buffer_in));
  element_init_Zr(y, pairing);
  element_from_bytes(y, y_buffer_in);
  element_init_G1(s, pairing);
  element_from_bytes(s, cert_buffer_in);
  element_init_G2(gpk, pairing);
  element_from_bytes(gpk, gpk_buffer_in);

  element_t g1, g2;
  element_init_G1(g1, pairing);
  element_init_G2(g2, pairing);
  element_from_bytes(g1, g1_buffer_in);
  element_from_bytes(g2, g2_buffer_in);

  element_t sig, p1, th11, th12, th21, th22, p11, p12, p21, p22, c1, c2, d1, d2, t2, t1;
  element_init_G1(sig, pairing);
  element_init_G1(c1, pairing);
  element_init_G1(c2, pairing);
  element_init_G1(d1, pairing);
  element_init_G1(d2, pairing);
  element_init_G1(t1, pairing);
  element_init_G1(t2, pairing);
  element_init_G1(p1, pairing);
  element_init_G1(th11, pairing);
  element_init_G1(th21, pairing);
  element_init_G1(th12, pairing);
  element_init_G1(th22, pairing);
  element_init_G2(p11, pairing);
  element_init_G2(p12, pairing);
  element_init_G2(p21, pairing);
  element_init_G2(p22, pairing);
  element_from_bytes(sig, sig_buffer_in);
  element_from_bytes(c1, c1_buffer_in);
  element_from_bytes(c2, c2_buffer_in);
  element_from_bytes(d1, d1_buffer_in);
  element_from_bytes(d2, d2_buffer_in);
  element_from_bytes(p1, p1_buffer_in);
  element_from_bytes(th11, th11_buffer_in);
  element_from_bytes(th21, th21_buffer_in);
  element_from_bytes(th12, th12_buffer_in);
  element_from_bytes(th22, th22_buffer_in);
  element_from_bytes(p11, p11_buffer_in);
  element_from_bytes(p12, p12_buffer_in);
  element_from_bytes(p21, p21_buffer_in);
  element_from_bytes(p22, p22_buffer_in);

  // Groth Sahai:
  element_t g11, g12, h11, h12, g21, g22, h21, h22;
  element_init_G1(g11, pairing);
  element_init_G1(g12, pairing);
  element_init_G1(h11, pairing);
  element_init_G1(h12, pairing);
  element_init_G2(g21, pairing);
  element_init_G2(g22, pairing);
  element_init_G2(h21, pairing);
  element_init_G2(h22, pairing);
  element_from_bytes(g11, g11_buffer_in);
  element_from_bytes(g12, g12_buffer_in);
  element_from_bytes(h11, h11_buffer_in);
  element_from_bytes(h12, h12_buffer_in);
  element_from_bytes(g21, g21_buffer_in);
  element_from_bytes(g22, g22_buffer_in);
  element_from_bytes(h21, h21_buffer_in);
  element_from_bytes(h22, h22_buffer_in);

  if (unittest)
  {
    element_printf("The server received : \n sig: %B, \n c1: %B, \n c2: %B, \n d1: %B, \n d2: %B, \n p1: %B, \n p11: %B,\n p12: %B, \n p21 : %B,\n, p22: %B, \n th11: %B,\n th12: %B,\n th21: %B,\n th22: %B,\n, g21 : %B, \n g22 : %B, \n g11 : %B, \n g12 : %B, \n h11 : %B, \n h12 : %B, \n", sig, c1, c2, d1, d2, p1, p11, p12, p21, p22, th11, th12, th21, th22, g21, g22, g11, g12, h11, h12);
  }



  // Then check each part of the proofs...
  element_t temp22;
  element_t temp1, temp2;
  element_init_GT(temp1, pairing);
  element_init_GT(temp2, pairing);
  element_init_G2(temp22, pairing);

  pairing_apply(temp1, sig, g22, pairing);
  pairing_apply(temp2, p1, g21, pairing);
  element_mul(temp1, temp1, temp2);
  pairing_apply(temp2, chal, c1, pairing);
  
  int test2 = element_cmp(temp1, temp2);
  result = result && !test2;
  if (unittest)
  {
    comp(test2, "GS eq 1-1 (sig)");
  }

  element_mul(temp22, g2, h22);
  pairing_apply(temp1, sig, temp22, pairing);
  pairing_apply(temp2, p1, h21, pairing);
  element_mul(temp1, temp1, temp2);
  pairing_apply(temp2, chal, c2, pairing);

  int test3 = element_cmp(temp1, temp2);
  result = result && !test3;
  if (unittest)
  {
    comp(test3, "GS eq 1-2 (sig)");
  }

  // At this stage, the server knows that the sig receives is valid under the key encrypted/commited in d1,d2... now let's check if this key is certfied

  element_t tt1, tt2, tt3, te2;
  element_init_GT(tt1, pairing);
  element_init_GT(tt2, pairing);
  element_init_GT(tt3, pairing);
  element_init_G2(te2, pairing);

  pairing_apply(tt1, d1, c1, pairing);
  pairing_apply(tt2, g11, p11, pairing);
  pairing_apply(tt3, g12, p21, pairing);
  element_mul(tt2, tt2, tt3);
  pairing_apply(tt3, th11, g21, pairing);
  element_mul(tt2, tt2, tt3);
  pairing_apply(tt3, th21, g22, pairing);
  element_mul(tt2, tt2, tt3);
  
  int test4 = element_cmp(tt1, tt2);
  result = result && !test4;
  if (unittest)
  {
    comp(test4, "GS eq 2-11");
  }

  // eq 2-12

  element_mul(te2, c2, gpk);
  pairing_apply(tt1, d1, te2, pairing);

  // e(u1,1, π1,2)e(u2,1, π2,2)e(θ1,1, v1,2)e(θ2,1, v2,2

  pairing_apply(tt2, g11, p12, pairing);
  pairing_apply(tt3, g12, p22, pairing);
  element_mul(tt2, tt2, tt3);
  pairing_apply(tt3, th11, h21, pairing);
  element_mul(tt2, tt2, tt3);
  pairing_apply(tt3, th21, h22, pairing);
  element_mul(tt2, tt2, tt3);
  
  int test5 = element_cmp(tt1, tt2);
  result = result && !test5;
  if (unittest)
  {
    comp(test5, "GS eq 2-12");
  }

  // eq 2-21

  element_mul(te2, c2, gpk);

  pairing_apply(tt1, d2, c1, pairing);
  // e(u1,2, π1,1)e(u2,2, π2,1)e(θ1,2, v1,1)e(θ2,2, v2,1)

  pairing_apply(tt2, h11, p11, pairing);
  pairing_apply(tt3, h12, p21, pairing);
  element_mul(tt2, tt2, tt3);
  pairing_apply(tt3, th12, g21, pairing);
  element_mul(tt2, tt2, tt3);
  pairing_apply(tt3, th22, g22, pairing);
  element_mul(tt2, tt2, tt3);

  int test6 = element_cmp(tt1, tt2);
  result = result && !test6;
  if (unittest)
  {
    comp(test6, "GS eq 2-21");
  }

  // eq 2-22

  element_mul(te2, c2, gpk);
  pairing_apply(tt1, d2, te2, pairing);
  //  tT e(u1,2, π1,2)e(u2,2, π2,2)e(θ1,2, v1,2)e(θ2,2, v2,2

  pairing_apply(tt2, h11, p12, pairing);
  pairing_apply(tt3, h12, p22, pairing);
  element_mul(tt2, tt2, tt3);
  pairing_apply(tt3, th12, h21, pairing);
  element_mul(tt2, tt2, tt3);
  pairing_apply(tt3, th22, h22, pairing);
  element_mul(tt2, tt2, tt3);
  pairing_apply(tt3, g1, g2, pairing);
  element_mul(tt2, tt2, tt3);

  int test7 = element_cmp(tt1, tt2);
  result = result && !test7;
  if (unittest)
  {
    comp(test7, "GS eq 2-22");
  }

   //Cleanup
  element_clear(y);
  element_clear(s);
  element_clear(gpk);
  element_clear(g1);
  element_clear(g2);
  element_clear(sig);
  element_clear(p1);
  element_clear(th11);
  element_clear(th12);
  element_clear(th21);
  element_clear(th22);
  element_clear(p11);
  element_clear(p12);
  element_clear(p21);
  element_clear(p22);
  element_clear(c1);
  element_clear(c2);
  element_clear(d1);
  element_clear(d2);
  element_clear(t1);
  element_clear(t2);
  element_clear(chal);
  element_clear(temp1);
  element_clear(temp2);
  element_clear(temp22);
  element_clear(tt1);
  element_clear(tt2);
  element_clear(tt3);
  element_clear(te2);

  pairing_clear(pairing);

  return result;
}
//-----------------------------------------------------------------------------
// Code des tiers de confiance
//-----------------------------------------------------------------------------
void trusted_sign_challenge(char *chal_buffer_in,
                            char *y_buffer_in,
                            char *cert_buffer_in,
                            char *gpk_buffer_in,
                            char *g1_buffer_in,
                            char *g2_buffer_in,
                            char *tk_buffer_in,
                            char *signed_chal_buffer_out,
                            char *c1_buffer_out,
                            char *c2_buffer_out,
                            char *d1_buffer_out,
                            char *d2_buffer_out,
                            char *p1_buffer_out,
                            char *p11_buffer_out,
                            char *p12_buffer_out,
                            char *p21_buffer_out,
                            char *p22_buffer_out,
                            char *th11_buffer_out,
                            char *th12_buffer_out,
                            char *th21_buffer_out,
                            char *th22_buffer_out,
                            char *g11_buffer_out,
                            char *g12_buffer_out,
                            char *h11_buffer_out,
                            char *h12_buffer_out,
                            char *g21_buffer_out,
                            char *g22_buffer_out,
                            char *h21_buffer_out,
                            char *h22_buffer_out)
{
  pairing_t pairing;
  setPairing(pairing);

  // load elements
  element_t chal, y, s, gpk, tk;
  element_init_G1(chal, pairing);
  element_from_hash(chal, chal_buffer_in, strlen(chal_buffer_in));
  element_init_Zr(y, pairing);
  element_from_bytes(y, y_buffer_in);
  element_init_G1(s, pairing);
  element_from_bytes(s, cert_buffer_in);
  element_init_G2(gpk, pairing);
  element_from_bytes(gpk, gpk_buffer_in);
  element_init_G2(tk, pairing);
  element_from_bytes(tk, tk_buffer_in);


  element_t g1, g2;
  element_init_G1(g1, pairing);
  element_init_G2(g2, pairing);
  element_from_bytes(g1, g1_buffer_in);
  element_from_bytes(g2, g2_buffer_in);

  // Groth Sahai:
  element_t g11, g12, h11, h12, g21, g22, h21, h22, dla, dlb;
  element_init_G1(g11, pairing);
  element_init_G1(g12, pairing);
  element_init_G1(h11, pairing);
  element_init_G1(h12, pairing);
  element_init_G2(g21, pairing);
  element_init_G2(g22, pairing);
  element_init_G2(h21, pairing);
  element_init_G2(h22, pairing);
  element_init_Zr(dla, pairing);
  element_init_Zr(dlb, pairing);

  // Soundness mode!  (No real reason to prefer one over the other, but less random call with this one... if preferred take all h random and disregard a,b)
  element_random(g11);
  element_random(g12);
  element_random(g21);
  element_random(g22);
  element_random(dla);
  element_random(dlb);
  element_pow_zn(h11, g11, dla);
  element_pow_zn(h12, g12, dla);
  element_pow_zn(h21, g21, dlb);
  element_pow_zn(h22, g22, dlb);

  element_t sig, p1, th11, th12, th21, th22, p11, p12, p21, p22, c1, c2, d1, d2, r1, r2, r3, t2, t1;

  element_init_G1(sig, pairing);
  element_pow_zn(sig, chal, y);

  // Generate the short GS proof!
  element_init_G1(c1, pairing);
  element_init_G1(c2, pairing);
  element_init_G1(t1, pairing);
  element_init_G1(t2, pairing);
  element_init_G1(p1, pairing);

  // commit y
  element_init_Zr(r1, pairing);
  element_random(r1);
  element_mul(t2, h22, g2);
  element_pow_zn(t2, t2, y);
  element_pow_zn(t1, h21, r1);
  element_mul(c2, t1, t2);
  element_pow_zn(t2, g22, y);
  element_pow_zn(t1, g21, r1);
  element_mul(c1, t1, t2);
  element_pow_zn(p1, chal, r1);

  if (unittest)
  {
    element_t temp1, temp2, temp22;
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_G2(temp22, pairing);

    pairing_apply(temp1, sig, g22, pairing);
    pairing_apply(temp2, p1, g21, pairing);
    element_mul(temp1, temp1, temp2);
    pairing_apply(temp2, chal, c1, pairing);
    comp(element_cmp(temp1, temp2), "GS eq 1-1 (sig)");

    element_mul(temp22, g2, h22);
    pairing_apply(temp1, sig, temp22, pairing);
    pairing_apply(temp2, p1, h21, pairing);
    element_mul(temp1, temp1, temp2);
    pairing_apply(temp2, chal, c2, pairing);
    comp(element_cmp(temp1, temp2), "GS eq 1-2 (sig)");
  }

  // Generate the looooong second proofs
  element_t te11, te12, te13, te21, te22, te23, tz1, tz2, t11, t12, t21, t22; // don't publish them, just auxialirary building component 1* is in G1, 2* in G2
  element_init_G1(te11, pairing);
  element_init_G1(te12, pairing);
  element_init_G1(te13, pairing);
  element_init_G2(te21, pairing);
  element_init_G2(te22, pairing);
  element_init_G2(te23, pairing);

  element_init_Zr(tz1, pairing); // intermediate exponent
  element_init_Zr(tz2, pairing); // intermediate exponent

  element_init_G1(d1, pairing);
  element_init_G1(d2, pairing);

  element_init_G1(th11, pairing);
  element_init_G1(th21, pairing);
  element_init_G1(th12, pairing);
  element_init_G1(th22, pairing);
  element_init_G2(p11, pairing);
  element_init_G2(p12, pairing);
  element_init_G2(p21, pairing);
  element_init_G2(p22, pairing);

  // commit s
  element_init_Zr(r2, pairing);
  element_init_Zr(r3, pairing);

  element_random(r2);
  element_random(r3);

  element_pow_zn(te11, g11, r2);
  element_pow_zn(te12, g12, r3);
  element_mul(d1, te11, te12);
  element_pow_zn(te11, h11, r2);
  element_pow_zn(te12, h12, r3);
  element_mul(d2, te11, te12);
  element_mul(d2, d2, s);
  //

  // Pick a random 2*2 matrix t:
  element_init_Zr(t11, pairing);
  element_init_Zr(t12, pairing);
  element_init_Zr(t21, pairing);
  element_init_Zr(t22, pairing);

  element_random(t11);
  element_random(t12);
  element_random(t21);
  element_random(t22);

  // let's start with pi... mmhh pi

  element_mul_zn(tz1, r2, r1);
  element_mul_si(tz2, t11, -1);
  element_add(tz1, tz1, tz2);
  element_pow_zn(te21, g21, tz1);
  element_mul_zn(tz1, r2, y);
  element_mul_si(tz2, t21, -1);
  element_add(tz1, tz1, tz2);
  element_pow_zn(te22, g22, tz1);
  element_mul(p11, te21, te22); // 1 out of 8 !! -> Valid

  element_mul_zn(tz1, r3, r1);
  element_mul_si(tz2, t12, -1);
  element_add(tz1, tz1, tz2);
  element_pow_zn(te21, g21, tz1);
  element_mul_zn(tz1, r3, y);
  element_mul_si(tz2, t22, -1);
  element_add(tz1, tz1, tz2);
  element_pow_zn(te22, g22, tz1);
  element_mul(p21, te21, te22); // 2 out of 8 !! -> Valid

  element_mul_zn(tz1, r2, r1);
  element_mul_si(tz2, t11, -1);
  element_add(tz1, tz1, tz2);
  element_pow_zn(te21, h21, tz1);
  element_mul_zn(tz1, r2, y);
  element_mul_si(tz2, t21, -1);
  element_add(tz1, tz1, tz2);
  element_pow_zn(te22, h22, tz1);
  element_mul(te21, te21, te22);
  element_mul(te22, gpk, tk);
  element_pow_zn(te22, te22, r2);
  element_mul(p12, te21, te22); // 3 out of 8 !!

  element_mul_zn(tz1, r3, r1);
  element_mul_si(tz2, t12, -1);
  element_add(tz1, tz1, tz2);
  element_pow_zn(te21, h21, tz1);
  element_mul_zn(tz1, r3, y);
  element_mul_si(tz2, t22, -1);
  element_add(tz1, tz1, tz2);
  element_pow_zn(te22, h22, tz1);
  element_mul(te21, te21, te22);
  element_mul(te22, gpk, tk);
  element_pow_zn(te22, te22, r3);
  element_mul(p22, te21, te22); // 4 out of 8 !!

  // No more pi :( let's switch to theta)

  element_pow_zn(te11, g11, t11);
  element_pow_zn(te12, g12, t12);
  element_mul(th11, te11, te12); // 5 out of 8 !! -> Valid

  element_pow_zn(te11, g11, t21);
  element_pow_zn(te12, g12, t22);
  element_mul(th21, te11, te12); // 6 out of 8 !! -> Valid

  element_pow_zn(te11, h11, t11);
  element_pow_zn(te12, h12, t12);
  element_mul(th22, te11, te12);
  element_pow_zn(te12, s, r1);
  element_mul(th12, th22, te12); // 7 out 8 -> valid

  element_pow_zn(te11, h11, t21);
  element_pow_zn(te12, h12, t22);
  element_mul(th22, te11, te12);
  element_pow_zn(te12, s, y);
  element_mul(th22, th22, te12); // 8 out of 8 !! -> valid

  if (unittest)
  {
    element_t tt1, tt2, tt3, te2;
    element_init_GT(tt1, pairing);
    element_init_GT(tt2, pairing);
    element_init_GT(tt3, pairing);
    element_init_G2(te2, pairing);

    pairing_apply(tt1, d1, c1, pairing);
    pairing_apply(tt2, g11, p11, pairing);
    pairing_apply(tt3, g12, p21, pairing);
    element_mul(tt2, tt2, tt3);
    pairing_apply(tt3, th11, g21, pairing);

    element_mul(tt2, tt2, tt3);
    pairing_apply(tt3, th21, g22, pairing);
    element_mul(tt2, tt2, tt3);

    comp(element_cmp(tt1, tt2), "GS eq 2-11");
    element_mul(te2, c2, gpk);
    pairing_apply(tt1, d1, te2, pairing);
    pairing_apply(tt2, g11, p12, pairing);
    pairing_apply(tt3, g12, p22, pairing);
    element_mul(tt2, tt2, tt3);
    pairing_apply(tt3, th11, h21, pairing);
    element_mul(tt2, tt2, tt3);
    pairing_apply(tt3, th21, h22, pairing);
    element_mul(tt2, tt2, tt3);
    comp(element_cmp(tt1, tt2), "GS eq 2-12");

    // eq 2-21

    element_mul(te2, c2, gpk);

    pairing_apply(tt1, d2, c1, pairing);
    // e(u1,2, π1,1)e(u2,2, π2,1)e(θ1,2, v1,1)e(θ2,2, v2,1)

    pairing_apply(tt2, h11, p11, pairing);
    pairing_apply(tt3, h12, p21, pairing);
    element_mul(tt2, tt2, tt3);
    pairing_apply(tt3, th12, g21, pairing);
    element_mul(tt2, tt2, tt3);
    pairing_apply(tt3, th22, g22, pairing);
    element_mul(tt2, tt2, tt3);
    comp(element_cmp(tt1, tt2), "GS eq 2-21");

    // eq 2-22

    element_mul(te2, c2, gpk);
    pairing_apply(tt1, d2, te2, pairing);
    //  tT e(u1,2, π1,2)e(u2,2, π2,2)e(θ1,2, v1,2)e(θ2,2, v2,2

    pairing_apply(tt2, h11, p12, pairing);
    pairing_apply(tt3, h12, p22, pairing);
    element_mul(tt2, tt2, tt3);
    pairing_apply(tt3, th12, h21, pairing);
    element_mul(tt2, tt2, tt3);
    pairing_apply(tt3, th22, h22, pairing);
    element_mul(tt2, tt2, tt3);
    pairing_apply(tt3, g1, g2, pairing);
    element_mul(tt2, tt2, tt3);
    comp(element_cmp(tt1, tt2), "GS eq 2-22");
  }
  
  if (unittest)
  {
    element_printf("The server sent : \n sig: %B, \n c1: %B, \n c2: %B, \n d1: %B, \n d2: %B, \n p1: %B, \n p11: %B,\n p12: %B, \n p21 : %B,\n, p22: %B, \n th11: %B,\n th12: %B,\n th21: %B,\n th22: %B,\n, g21 : %B, \n g22 : %B, \n g11 : %B, \n g12 : %B, \n h11 : %B, \n h12 : %B, \n", sig, c1, c2, d1, d2, p1, p11, p12, p21, p22, th11, th12, th21, th22, g21, g22, g11, g12, h11, h12);
  }

  element_to_bytes(signed_chal_buffer_out, sig);
  element_to_bytes(c1_buffer_out, c1);
  element_to_bytes(c2_buffer_out, c2);
  element_to_bytes(d1_buffer_out, d1);
  element_to_bytes(d2_buffer_out, d2);
  element_to_bytes(p1_buffer_out, p1);
  element_to_bytes(p11_buffer_out, p11);
  element_to_bytes(p12_buffer_out, p12);
  element_to_bytes(p21_buffer_out, p21);
  element_to_bytes(p22_buffer_out, p22);
  element_to_bytes(th11_buffer_out, th11);
  element_to_bytes(th12_buffer_out, th12);
  element_to_bytes(th21_buffer_out, th21);
  element_to_bytes(th22_buffer_out, th22);
  element_to_bytes(g11_buffer_out, g11);
  element_to_bytes(g12_buffer_out, g12);
  element_to_bytes(h11_buffer_out, h11);
  element_to_bytes(h12_buffer_out, h12);
  element_to_bytes(g21_buffer_out, g21);
  element_to_bytes(g22_buffer_out, g22);
  element_to_bytes(h21_buffer_out, h21);
  element_to_bytes(h22_buffer_out, h22);

  //Cleanup
  element_clear(chal);
  element_clear(y);
  element_clear(s);
  element_clear(gpk);
  element_clear(tk);
  element_clear(g1);
  element_clear(g2);
  element_clear(g11);
  element_clear(g12);
  element_clear(h11);
  element_clear(h12);
  element_clear(g21);
  element_clear(g22);
  element_clear(h21);
  element_clear(h22);
  element_clear(dla);
  element_clear(dlb);
  element_clear(sig);
  element_clear(p1);
  element_clear(th11);
  element_clear(th12);
  element_clear(th21);
  element_clear(th22);
  element_clear(p11);

  element_clear(p12);
  element_clear(p21);
  element_clear(p22);
  element_clear(c1);
  element_clear(c2);
  element_clear(d1);
  element_clear(d2);
  element_clear(r1);

  element_clear(r2);
  element_clear(r3);
  element_clear(t2);
  element_clear(t1);
  element_clear(te11);
  element_clear(te12);
  element_clear(te13);

   element_clear(te21);
  element_clear(te22);
  element_clear(te23);
  element_clear(tz1);
  element_clear(tz2);
  element_clear(t11);
  element_clear(t12);
  element_clear(t21);
  element_clear(t22);


  pairing_clear(pairing);
}