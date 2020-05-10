/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#include "target.h" 

uint8_t char2hex(char x){
  uint8_t hex[16] = "0123456789abcdef";
  uint8_t HEX[16] = "0123456789ABCDEF";
  for(int i = 0; i<16; i++){
    if (x == hex[i]||x == HEX[i]) return i;
  }
  return -1;
}

uint8_t hex2char(uint8_t x){
  uint8_t hex[16] = "0123456789abcdef";
  if (x < 16) return hex[x];
  return -1;
}


/** Read  an octet string (or sequence of bytes) from the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  * 
  * \param[out] r the destination octet string read
  * \return       the number of octets read
  */

int  octetstr_rd(       uint8_t* r, int n_r ) {
  uint8_t msb,lsb;
  int actual = 0;
  char prefix = scale_uart_rd(SCALE_UART_MODE_BLOCKING);

  //Determine length
  while (prefix != ':'){
    actual = actual << 4;
    actual += char2hex(prefix);
    prefix = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
  }

  //If buffer to small then error
  if (n_r < actual) return -1;
  
  //Read the length
  for(int i = 0; i < actual; i++){
    msb = scale_uart_rd(SCALE_UART_MODE_BLOCKING);

    lsb = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
    
    r[i] = (char2hex(msb) << 4) + char2hex(lsb);
  }
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, '\r' );
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, '\n' );
  return actual;
}

/** Write an octet string (or sequence of bytes) to   the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  * 
  * \param[in]  r the source      octet string written
  * \param[in]  n the number of octets written
  */

void octetstr_wr( const uint8_t* x, int n_x ) {
  char msb, lsb;
  int prefix;

  // Convert the int n_x into hex
  bool foundmsb = false;
  for( int i = sizeof(int) * 2; i >= 0; i--){
    prefix = (n_x >> (4 * i)) & 0xf;
    if (prefix!=0){
      foundmsb = true;
    }
    if (foundmsb == true) scale_uart_wr(SCALE_UART_MODE_BLOCKING,hex2char(prefix));
  }

  scale_uart_wr( SCALE_UART_MODE_BLOCKING, ':' );


  // Write the octet string
  for( int i = 0; i < n_x; i++ ) {
      msb = hex2char(x[i] >> 4);
      lsb = hex2char(x[i] & 0xf);
      scale_uart_wr( SCALE_UART_MODE_BLOCKING, msb );
      scale_uart_wr( SCALE_UART_MODE_BLOCKING, lsb );

    }
    scale_uart_wr( SCALE_UART_MODE_BLOCKING, '\r' );
    scale_uart_wr( SCALE_UART_MODE_BLOCKING, '\n' );
    return;
}

// Calculate the resulting mask after performing mix columns
void computeMixMask(aes_gf28_t* mask){
  aes_gf28_t __a1 = mask[2];\
  aes_gf28_t __b1 = mask[3];\
  aes_gf28_t __c1 = mask[4];\
  aes_gf28_t __d1 = mask[5];\
  \
  aes_gf28_t __a2 = aes_gf28_mulx( __a1 );\
  aes_gf28_t __b2 = aes_gf28_mulx( __b1 );\
  aes_gf28_t __c2 = aes_gf28_mulx( __c1 );\
  aes_gf28_t __d2 = aes_gf28_mulx( __d1 );\
  \
  aes_gf28_t __a3 = __a1 ^ __a2;\
  aes_gf28_t __b3 = __b1 ^ __b2;\
  aes_gf28_t __c3 = __c1 ^ __c2;\
  aes_gf28_t __d3 = __d1 ^ __d2;\
  \
  mask[6] = __a2 ^ __b3 ^ __c1 ^ __d1;\
  mask[7] = __a1 ^ __b2 ^ __c3 ^ __d1;\
  mask[8] = __a1 ^ __b1 ^ __c2 ^ __d3;\
  mask[9] = __a3 ^ __b1 ^ __c1 ^ __d2;\
}

// Compute the masked sbox
void maskSBox(aes_gf28_t* mask){
  for (int i=0; i<256; i++){
    mbox[i^mask[0]] = sbox[i] ^ mask[1];
  }
}

// Mask a 4x4 matrix, either state or key
void mask16(aes_gf28_t* state,aes_gf28_t m1,aes_gf28_t m2,aes_gf28_t m3,aes_gf28_t m4){
  state[0]  ^= m1; state[1]  ^= m2; state[2]  ^= m3; state[3]  ^= m4;
  state[4]  ^= m1; state[5]  ^= m2; state[6]  ^= m3; state[7]  ^= m4;
  state[8]  ^= m1; state[9]  ^= m2; state[10] ^= m3; state[11] ^= m4;
  state[12] ^= m1; state[13] ^= m2; state[14] ^= m3; state[15] ^= m4;

}

// Initial masking of the state and key
void maskStateAndKey(aes_gf28_t* state, aes_gf28_t* key, aes_gf28_t* mask){
  mask16(state,mask[6],mask[7],mask[8],mask[9]);
  mask16(key,mask[0]^mask[6],mask[0]^mask[7],mask[0]^mask[8],mask[0]^mask[9]);
}

aes_gf28_t aes_gf28_add( aes_gf28_t a, aes_gf28_t b ){
  return a ^ b;
}

aes_gf28_t aes_gf28_mulx( aes_gf28_t a ){
  if( ( a & 0x80 ) == 0x80 ){
    return 0x1B ^ ( a << 1 );
  }
  else{
    return( a << 1 );
  }
}

/*
  Multiply two polynomials
*/
aes_gf28_t aes_gf28_mul(aes_gf28_t a, aes_gf28_t b){
  aes_gf28_t t = 0;

  for(int i = 7; i >= 0; i--){
    t = aes_gf28_mulx(t);

    if ((b >> i ) & 1){
      t ^= a; 
    }
  }
  return t;
}

// Apply the SBox
aes_gf28_t aes_enc_sbox( aes_gf28_t a ){
    return sbox[a];
}

// Apply the MaskedSbox
aes_gf28_t aes_enc_mbox( aes_gf28_t a ){
    return mbox[a];
}

void aes_enc_keyexp_step(uint8_t* r, const uint8_t* rk, uint8_t rc){
    r[ 0] = rc ^ aes_enc_sbox(rk[13]) ^ rk[ 0];
    r[ 1] =      aes_enc_sbox(rk[14]) ^ rk[ 1];
    r[ 2] =      aes_enc_sbox(rk[15]) ^ rk[ 2];
    r[ 3] =      aes_enc_sbox(rk[12]) ^ rk[ 3];

    r[ 4] =                    r[ 0]  ^ rk[ 4];
    r[ 5] =                    r[ 1]  ^ rk[ 5];
    r[ 6] =                    r[ 2]  ^ rk[ 6];
    r[ 7] =                    r[ 3]  ^ rk[ 7];

    r[ 8] =                    r[ 4]  ^ rk[ 8];
    r[ 9] =                    r[ 5]  ^ rk[ 9];
    r[10] =                    r[ 6]  ^ rk[10];
    r[11] =                    r[ 7]  ^ rk[11];

    r[12] =                    r[ 8]  ^ rk[12];
    r[13] =                    r[ 9]  ^ rk[13];
    r[14] =                    r[10]  ^ rk[14];
    r[15] =                    r[11]  ^ rk[15];
}

void aes_enc_rnd_key(aes_gf28_t* s, const aes_gf28_t* rk){
    for(int i = 0; i < 16; i++){
        s[i] = s[i] ^ rk[i];
    }
}

void aes_enc_rnd_sub(aes_gf28_t* s){
    for( int i = 0; i < 16; i++){
        s[i] = aes_enc_mbox(s[i]);
    }
}



void aes_enc_rnd_row( aes_gf28_t* s){
    AES_ENC_RND_ROW_STEP(  1,  5,  9, 13,
                          13,  1,  5,  9);
    AES_ENC_RND_ROW_STEP(  2,  6, 10, 14,
                          10, 14,  2,  6);
    AES_ENC_RND_ROW_STEP(  3,  7, 11, 15, 
                           7, 11, 15,  3);
}



void aes_enc_rnd_mix(aes_gf28_t* s){
    AES_ENC_RND_MIX_STEP(  0,  1,  2,  3);
    AES_ENC_RND_MIX_STEP(  4,  5,  6,  7);
    AES_ENC_RND_MIX_STEP(  8,  9, 10, 11);
    AES_ENC_RND_MIX_STEP( 12, 13, 14, 15);
}

/** Initialise an AES-128 encryption, e.g., expand the cipher key k into round
  * keys, or perform randomised pre-computation in support of a countermeasure;
  * this can be left blank if no such initialisation is required, because the
  * same k and r will be passed as input to the encryption itself.
  * 
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes_init(const uint8_t* k, const uint8_t* r ) {
  //Make round key
  memcpy(keySchedule[0],k,16);
  memcpy(mask,r,6);


  maskSBox(mask);
  computeMixMask(mask);
  for(int i = 1; i < Nr; i++){
    aes_enc_keyexp_step(keySchedule[i],keySchedule[i-1],AES_RC[i]);
    mask16(keySchedule[i-1],mask[0]^mask[6],mask[0]^mask[7],mask[0]^mask[8],mask[0]^mask[9]);
  }
  aes_enc_keyexp_step(keySchedule[Nr],keySchedule[Nr-1],AES_RC[Nr]);
  mask16(keySchedule[Nr-1],mask[0]^mask[6],mask[0]^mask[7],mask[0]^mask[8],mask[0]^mask[9]);
  mask16(keySchedule[Nr],mask[1],mask[1],mask[1],mask[1]);
  return;
}

/** Perform    an AES-128 encryption of a plaintext m under a cipher key k, to
  * yield the corresponding ciphertext c.
  * 
  * \param[out] c   an   AES-128 ciphertext
  * \param[in]  m   an   AES-128 plaintext
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes     ( uint8_t* c, const uint8_t* m, const uint8_t* k, const uint8_t* r ) {
    aes_gf28_t rk[4 * Nb], s[ 4 * Nb];

    aes_gf28_t* rkp = keySchedule[0];

    memcpy(s,m,16);
    
    maskStateAndKey(s,rk,mask);

    //1 initial round
    aes_enc_rnd_key(s,rkp);
    //Nr - 1 rounds
    rkp = keySchedule[1];
    for( int i = 1; i<Nr; i++){
        aes_enc_rnd_sub(s);
        aes_enc_rnd_row(s);
        // Remask the state
        mask16(s,mask[1]^mask[2],mask[1]^mask[3],mask[1]^mask[4],mask[1]^mask[5]);
        aes_enc_rnd_mix(s);

        // Unmask and remask the key for key exponentiation
        // mask16(rk,mask[0]^mask[6],mask[0]^mask[7],mask[0]^mask[8],mask[0]^mask[9]);
        // aes_enc_keyexp_step(rkp,rkp,*(++rcp));
        // mask16(rk,mask[0]^mask[6],mask[0]^mask[7],mask[0]^mask[8],mask[0]^mask[9]);

        aes_enc_rnd_key(s,rkp);
        rkp = keySchedule[i+1];

    }
    //Final round
    aes_enc_rnd_sub(s);
    aes_enc_rnd_row(s);

    // Unmask, but remask with a different mask in order to give unmasked end result
    // mask16(rk,mask[0]^mask[6],mask[0]^mask[7],mask[0]^mask[8],mask[0]^mask[9]);
    // aes_enc_keyexp_step(rkp,rkp,*(++rcp));
    // mask16(rk,mask[1],mask[1],mask[1],mask[1]);

    aes_enc_rnd_key(s,rkp);

    memcpy(c,s,16);
    return;
}

/** Initialise the SCALE development board, then loop indefinitely, reading a
  * command then processing it:
  *
  * 1. If command is inspect, then
  *
  *    - write the SIZEOF_BLK parameter,
  *      i.e., number of bytes in an  AES-128 plaintext  m, or ciphertext c,
  *      to the UART, 
  *    - write the SIZEOF_KEY parameter,
  *      i.e., number of bytes in an  AES-128 cipher key k,
  *      to the UART, 
  *    - write the SIZEOF_RND parameter,
  *      i.e., number of bytes in the         randomness r.
  *      to the UART.
  *
  * 2. If command is encrypt, then
  *
  *    - read  an   AES-128 plaintext  m from the UART,
  *    - read  some         randomness r from the UART,
  *    - initalise the encryption,
  *    - set the trigger signal to 1,
  *    - execute   the encryption, producing the ciphertext 
  *
  *      c = AES-128.Enc( m, k )
  *
  *      using the hard-coded cipher key k plus randomness r if/when need be,
  *    - set the trigger signal to 0,
  *    - write an   AES-128 ciphertext c to   the UART.
  */

int main( int argc, char* argv[] ) {
  scale_conf_t scale_conf = {
    .clock_type        = SCALE_CLOCK_TYPE_EXT,
    .clock_freq_source = SCALE_CLOCK_FREQ_16MHZ,
    .clock_freq_target = SCALE_CLOCK_FREQ_16MHZ,

    .tsc               = false
  };

  if( !scale_init( &scale_conf ) ) {
    return -1;
  }

  uint8_t cmd[ 1 ], c[ SIZEOF_BLK ], m[ SIZEOF_BLK ], k[ SIZEOF_KEY ] = { 0x38, 0x2D, 0x8B, 0x3E, 0x62, 0x7B, 0x9A, 0x10, 0xD2, 0x02, 0xF3, 0x3E, 0x8E, 0x85, 0x2B, 0x83 }, r[ SIZEOF_RND ];

  while( true ) {
    if( 1 != octetstr_rd( cmd, 1 ) ) {
      break;
    }

    switch( cmd[ 0 ] ) {
      case COMMAND_INSPECT : {
        uint8_t t = SIZEOF_BLK; 
                    octetstr_wr( &t, 1 ); 
                t = SIZEOF_KEY; 
                    octetstr_wr( &t, 1 ); 
                t = SIZEOF_RND; 
                    octetstr_wr( &t, 1 ); 

        break;
      }
      case COMMAND_ENCRYPT : {
        if( SIZEOF_BLK != octetstr_rd( m, SIZEOF_BLK ) ) {
          break;
        }
        if( SIZEOF_RND != octetstr_rd( r, SIZEOF_RND ) ) {
          break;
        }

        aes_init(       k, r );

        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  true );
        aes     ( c, m, k, r );
        scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );

        octetstr_wr( c, SIZEOF_BLK );

        break;
      }
      default : {
        break;
      }
    }
  }

  return 0;
}
