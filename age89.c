/*
 * age89.verbose.c - age89 with optional diagnostic logging
 *
 * Use the -v flag to print each derivation step to stderr.
 * Useful for debugging cross-platform differences (Unix vs MSVC 6 / Windows 98).
 *
 * Build (gcc):  gcc -ansi -pedantic -O0 -o age89v age89.verbose.c
 * Build (MSVC): cl /Za /Od age89.verbose.c
 *
 * Algorithms: X25519, ChaCha20-Poly1305, HKDF-SHA256, scrypt, Bech32
 *
 * Usage:
 *   Generate key pair:     age89 -k
 *   Encrypt (public key):  age89 -e -r age1PUBKEY [-o OUTPUT] [INPUT]
 *   Encrypt (passphrase):  age89 -e -p [-o OUTPUT] [INPUT]
 *   Decrypt (private key): age89 -d -i AGE-SECRET-KEY-1... [-o OUTPUT] [INPUT]
 *   Decrypt (passphrase):  age89 -d -p [-o OUTPUT] [INPUT]
 *
 * C89 CHANGES vs original:
 *   - u64/s64 emulated with two u32 (hi + lo)
 *   - All variable declarations moved to top of each block
 *   - Removed all double-slash comments, only block comments used
 *   - Removed 1LL literals, replaced with u64/s64 helpers
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32; /* int = 32 bits on MSVC6/Win98, 32-bit Linux, and 64-bit Mac/Linux */

/* ================================================================
 * VERBOSE DIAGNOSTIC LOGGING
 * All output goes to stderr so stdout binary data is not corrupted.
 * Enabled only when the -v flag is passed.
 * ================================================================ */

static int verbose = 0;

static void dbg_hex(const char *lbl, const u8 *d, int n)
{
    int i;
    if(!verbose) return;
    fprintf(stderr,"%s (%d bytes):\n",lbl,n);
    for(i=0;i<n;i++){
        if(i%16==0) fprintf(stderr,"  %04x: ",i);
        fprintf(stderr,"%02x",d[i]);
        if(i%16==15||i==n-1) fprintf(stderr,"\n");
        else fprintf(stderr," ");
    }
}

static void dbg_str(const char *lbl, const char *s)
{
    if(!verbose) return;
    fprintf(stderr,"%s: \"%s\"\n",lbl,s);
}

/* ================================================================
 * 64-BIT EMULATION USING TWO u32
 * hi = upper 32 bits, lo = lower 32 bits
 * ================================================================ */

typedef struct { u32 lo; u32 hi; } u64;
typedef struct { u32 lo; u32 hi; } s64; /* signed: hi bit 31 = sign */

/* Build a u64 from two u32 */
static u64 u64_from32(u32 v)
{
    u64 r;
    r.hi = 0; r.lo = v;
    return r;
}

/* Build a s64 from a single u32 (zero-extend, always positive) */
static s64 s64_from32(u32 v)
{
    s64 r;
    r.hi = 0; r.lo = v;
    return r;
}

/* u64 addition */
static u64 u64_add(u64 a, u64 b)
{
    u64 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1u : 0u);
    return r;
}

/* s64 addition (same bit pattern as u64_add) */
static s64 s64_add(s64 a, s64 b)
{
    s64 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1u : 0u);
    return r;
}

/* s64 subtraction */
static s64 s64_sub(s64 a, s64 b)
{
    s64 r;
    r.lo = a.lo - b.lo;
    r.hi = a.hi - b.hi - (a.lo < b.lo ? 1u : 0u);
    return r;
}

/* u64 subtraction */
static u64 u64_sub(u64 a, u64 b)
{
    u64 r;
    r.lo = a.lo - b.lo;
    r.hi = a.hi - b.hi - (a.lo < b.lo ? 1u : 0u);
    return r;
}

/* u64 multiply: only lower 64 bits (sufficient for scrypt counters) */
static u64 u64_mul(u64 a, u64 b)
{
    u64 r;
    u32 a0, a1, b0, b1;
    u32 mid, lo;
    a0 = a.lo & 0xffffu; a1 = a.lo >> 16;
    b0 = b.lo & 0xffffu; b1 = b.lo >> 16;
    lo = a0 * b0;
    mid = (a0 * b1) + (a1 * b0) + (lo >> 16);
    r.lo = (mid << 16) | (lo & 0xffffu);
    r.hi = a.hi * b.lo + a.lo * b.hi + (a1 * b1) + (mid >> 16);
    return r;
}

/* s64 multiply: lower 64 bits of a*b, correct for signed values.
 * a*b mod 2^64 = lo32(a)*lo32(b) + [hi32(a)*lo32(b) + lo32(a)*hi32(b)] * 2^32
 * We split lo32 into two 16-bit halves to avoid 32-bit overflow. */
static s64 s64_mul(s64 a, s64 b)
{
    s64 r;
    u32 a0, a1, b0, b1;
    u32 p00, p01, p10, mid, carry;
    a0 = a.lo & 0xffffu; a1 = a.lo >> 16;
    b0 = b.lo & 0xffffu; b1 = b.lo >> 16;
    p00 = a0 * b0;
    p01 = a0 * b1;
    p10 = a1 * b0;
    mid   = (p00 >> 16) + (p01 & 0xffffu) + (p10 & 0xffffu);
    carry = (mid >> 16)  + (p01 >> 16)    + (p10 >> 16) + a1 * b1;
    r.lo  = (mid << 16) | (p00 & 0xffffu);
    r.hi  = a.lo * b.hi + a.hi * b.lo + carry;
    return r;
}

/* u64 logical shift right */
static u64 u64_shr(u64 a, int n)
{
    u64 r;
    if(n == 0)  { r = a; }
    else if(n < 32) {
        r.lo = (a.lo >> n) | (a.hi << (32 - n));
        r.hi = a.hi >> n;
    } else {
        r.lo = a.hi >> (n - 32);
        r.hi = 0;
    }
    return r;
}

/* s64 arithmetic shift right */
static s64 s64_sar(s64 a, int n)
{
    s64 r;
    if(n == 0) { r = a; }
    else if(n < 32) {
        r.lo = (a.lo >> n) | (a.hi << (32 - n));
        r.hi = (u32)((int)a.hi >> n);
    } else {
        r.lo = (u32)((int)a.hi >> (n - 32));
        r.hi = (u32)((int)a.hi >> 31);
    }
    return r;
}

/* u64 logical shift left */
static u64 u64_shl(u64 a, int n)
{
    u64 r;
    if(n == 0) { r = a; }
    else if(n < 32) {
        r.hi = (a.hi << n) | (a.lo >> (32 - n));
        r.lo = a.lo << n;
    } else {
        r.hi = a.lo << (n - 32);
        r.lo = 0;
    }
    return r;
}

/* s64 shift left */
static s64 s64_shl(s64 a, int n)
{
    s64 r;
    if(n == 0) { r = a; }
    else if(n < 32) {
        r.hi = (a.hi << n) | (a.lo >> (32 - n));
        r.lo = a.lo << n;
    } else {
        r.hi = a.lo << (n - 32);
        r.lo = 0;
    }
    return r;
}

/* u64 bitwise AND */
static u64 u64_and(u64 a, u64 b)
{
    u64 r;
    r.lo = a.lo & b.lo;
    r.hi = a.hi & b.hi;
    return r;
}

/* s64 bitwise AND */
static s64 s64_and(s64 a, s64 b)
{
    s64 r;
    r.lo = a.lo & b.lo;
    r.hi = a.hi & b.hi;
    return r;
}

/* s64 bitwise XOR */
static s64 s64_xor(s64 a, s64 b)
{
    s64 r;
    r.lo = a.lo ^ b.lo;
    r.hi = a.hi ^ b.hi;
    return r;
}

/* s64 bitwise NOT */
static s64 s64_not(s64 a)
{
    s64 r;
    r.lo = ~a.lo;
    r.hi = ~a.hi;
    return r;
}

/* u64 less-than comparison */
static int u64_lt(u64 a, u64 b)
{
    if(a.hi != b.hi) return a.hi < b.hi;
    return a.lo < b.lo;
}

/* extract low/high 32 bits */
static u32 u64_lo32(u64 a) { return a.lo; }
static u32 u64_hi32(u64 a) { return a.hi; }
static u32 s64_lo32(s64 a) { return a.lo; }

/* store u64 little-endian */
static void u64_store_le(u8 *b, u64 x)
{
    b[0]=(u8)x.lo;      b[1]=(u8)(x.lo>>8);  b[2]=(u8)(x.lo>>16); b[3]=(u8)(x.lo>>24);
    b[4]=(u8)x.hi;      b[5]=(u8)(x.hi>>8);  b[6]=(u8)(x.hi>>16); b[7]=(u8)(x.hi>>24);
}

/* u64 increment */
static u64 u64_inc(u64 a)
{
    return u64_add(a, u64_from32(1u));
}

/* s64 constant: value 1 */
static s64 s64_one(void)
{
    s64 r; r.lo = 1; r.hi = 0;
    return r;
}

/* s64 from signed int */
static s64 s64_from_int(int v)
{
    s64 r;
    r.lo = (u32)v;
    r.hi = (v < 0) ? 0xffffffffu : 0u;
    return r;
}

/* s64 to int (low 32 bits, for use as array index etc.) */
static int s64_to_int(s64 a) { return (int)a.lo; }

/* s64 multiply by small int */
static s64 s64_mul_int(s64 a, int b)
{
    return s64_mul(a, s64_from_int(b));
}

/* ================================================================
 * UTILITIES
 * ================================================================ */

static void mem_wipe(void *p, size_t n)
{
    volatile u8 *v = (volatile u8 *)p;
    while (n--) *v++ = 0;
}

static u32 load32_le(const u8 *b)
{
    return (u32)b[0]|((u32)b[1]<<8)|((u32)b[2]<<16)|((u32)b[3]<<24);
}
static void store32_le(u8 *b, u32 x)
{
    b[0]=(u8)x; b[1]=(u8)(x>>8); b[2]=(u8)(x>>16); b[3]=(u8)(x>>24);
}
static u32 load32_be(const u8 *b)
{
    return ((u32)b[0]<<24)|((u32)b[1]<<16)|((u32)b[2]<<8)|(u32)b[3];
}
static void store32_be(u8 *b, u32 x)
{
    b[0]=(u8)(x>>24); b[1]=(u8)(x>>16); b[2]=(u8)(x>>8); b[3]=(u8)x;
}
static void store64_le(u8 *b, u64 x)
{
    u64_store_le(b, x);
}
static u32 rotl32(u32 x, int n) { return (x<<n)|(x>>(32-n)); }

/* ASCII tolower (defined before bech32) */
static int ascii_tolower(int c)
{
    if (c>='A' && c<='Z') return c+32;
    return c;
}

/* ================================================================
 * SHA-256
 * ================================================================ */

typedef struct { u32 s[8]; u64 n; u8 b[64]; int bl; } sha256_ctx;

static const u32 sha256_K[64]={
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
    0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
    0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
    0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
    0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
    0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
    0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
    0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
    0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

static void sha256_transform(sha256_ctx *ctx, const u8 *blk)
{
    u32 w[64],a,b,c,d,e,f,g,h,t1,t2,s0,s1;
    int i;
    for(i=0;i<16;i++) w[i]=load32_be(blk+i*4);
    for(i=16;i<64;i++){
        s0=rotl32(w[i-15],25)^rotl32(w[i-15],14)^(w[i-15]>>3);
        s1=rotl32(w[i-2],15)^rotl32(w[i-2],13)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    a=ctx->s[0];b=ctx->s[1];c=ctx->s[2];d=ctx->s[3];
    e=ctx->s[4];f=ctx->s[5];g=ctx->s[6];h=ctx->s[7];
    for(i=0;i<64;i++){
        t1=h+(rotl32(e,26)^rotl32(e,21)^rotl32(e,7))+((e&f)^(~e&g))+sha256_K[i]+w[i];
        t2=(rotl32(a,30)^rotl32(a,19)^rotl32(a,10))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->s[0]+=a;ctx->s[1]+=b;ctx->s[2]+=c;ctx->s[3]+=d;
    ctx->s[4]+=e;ctx->s[5]+=f;ctx->s[6]+=g;ctx->s[7]+=h;
}
static void sha256_init(sha256_ctx *ctx)
{
    ctx->s[0]=0x6a09e667UL;ctx->s[1]=0xbb67ae85UL;
    ctx->s[2]=0x3c6ef372UL;ctx->s[3]=0xa54ff53aUL;
    ctx->s[4]=0x510e527fUL;ctx->s[5]=0x9b05688cUL;
    ctx->s[6]=0x1f83d9abUL;ctx->s[7]=0x5be0cd19UL;
    ctx->n = u64_from32(0);
    ctx->bl=0;
}
static void sha256_update(sha256_ctx *ctx, const u8 *d, size_t len)
{
    size_t i;
    for(i=0;i<len;i++){
        ctx->b[ctx->bl++]=d[i];
        ctx->n = u64_add(ctx->n, u64_from32(1u));
        if(ctx->bl==64){sha256_transform(ctx,ctx->b);ctx->bl=0;}
    }
}
static void sha256_final(sha256_ctx *ctx, u8 *out)
{
    u8 pad[64];
    u64 bits;
    int pl,i;
    bits = u64_shl(ctx->n, 3); /* bits = n * 8 */
    memset(pad,0,64); pad[0]=0x80;
    pl=(ctx->bl<56)?(56-ctx->bl):(120-ctx->bl);
    sha256_update(ctx,pad,(size_t)pl);
    pad[0]=(u8)(bits.hi>>24);pad[1]=(u8)(bits.hi>>16);
    pad[2]=(u8)(bits.hi>>8); pad[3]=(u8)(bits.hi);
    pad[4]=(u8)(bits.lo>>24);pad[5]=(u8)(bits.lo>>16);
    pad[6]=(u8)(bits.lo>>8); pad[7]=(u8)(bits.lo);
    sha256_update(ctx,pad,8);
    for(i=0;i<8;i++) store32_be(out+i*4,ctx->s[i]);
}
static void sha256_hash(const u8 *d, size_t n, u8 *out)
{
    sha256_ctx c;
    sha256_init(&c); sha256_update(&c,d,n); sha256_final(&c,out);
    mem_wipe(&c,sizeof(c));
}

/* ================================================================
 * HMAC-SHA256
 * ================================================================ */

typedef struct { sha256_ctx in, out; } hmac_ctx;

static void hmac_init(hmac_ctx *ctx, const u8 *key, size_t klen)
{
    u8 k[64],ip[64],op[64];
    int i;
    memset(k,0,64);
    if(klen>64) sha256_hash(key,klen,k); else memcpy(k,key,klen);
    for(i=0;i<64;i++){ip[i]=k[i]^0x36;op[i]=k[i]^0x5c;}
    sha256_init(&ctx->in);  sha256_update(&ctx->in,ip,64);
    sha256_init(&ctx->out); sha256_update(&ctx->out,op,64);
    mem_wipe(k,64);
}
static void hmac_update(hmac_ctx *ctx, const u8 *d, size_t n)
{
    sha256_update(&ctx->in,d,n);
}
static void hmac_final(hmac_ctx *ctx, u8 *mac)
{
    u8 t[32];
    sha256_final(&ctx->in,t);
    sha256_update(&ctx->out,t,32); sha256_final(&ctx->out,mac);
    mem_wipe(t,32);
}
static void hmac_sha256(const u8 *k, size_t kl, const u8 *d, size_t dl, u8 *mac)
{
    hmac_ctx c;
    hmac_init(&c,k,kl); hmac_update(&c,d,dl); hmac_final(&c,mac);
    mem_wipe(&c,sizeof(c));
}

/* ================================================================
 * HKDF-SHA256
 * ================================================================ */

static void hkdf_sha256(const u8 *ikm, size_t il, const u8 *salt, size_t sl,
                         const u8 *info, size_t nl, u8 *out, size_t ol)
{
    static const u8 z32[32]={0};
    u8 prk[32],t[32];
    hmac_ctx c;
    size_t done;
    u8 ctr;
    if(verbose) fprintf(stderr,"[HKDF] --- hkdf_sha256 begin ---\n");
    dbg_hex("[HKDF] IKM", ikm, (int)il);
    if(salt&&sl) { dbg_hex("[HKDF] salt", salt, (int)sl); hmac_sha256(salt,sl,ikm,il,prk); }
    else         { if(verbose) fprintf(stderr,"[HKDF] salt: (null -> 32 zero bytes)\n"); hmac_sha256(z32,32,ikm,il,prk); }
    dbg_hex("[HKDF] PRK (extract)", prk, 32);
    if(info&&nl) dbg_hex("[HKDF] info", info, (int)nl);
    else { if(verbose) fprintf(stderr,"[HKDF] info: (none)\n"); }
    done=0; ctr=0;
    while(done<ol){
        size_t chunk;
        ctr++;        hmac_init(&c,prk,32);
        if(done>0) hmac_update(&c,t,32);
        if(info&&nl) hmac_update(&c,info,nl);
        hmac_update(&c,&ctr,1);
        hmac_final(&c,t);
        chunk=ol-done; if(chunk>32)chunk=32;
        memcpy(out+done,t,chunk); done+=chunk;
    }
    dbg_hex("[HKDF] OUT (expand)", out, (int)ol);
    if(verbose) fprintf(stderr,"[HKDF] --- hkdf_sha256 end ---\n");
    mem_wipe(prk,32); mem_wipe(t,32); mem_wipe(&c,sizeof(c));
}

/* ================================================================
 * PBKDF2-HMAC-SHA256
 * ================================================================ */

static void pbkdf2_sha256(const u8 *pw, size_t pl, const u8 *salt, size_t sl,
                           u32 iters, u8 *out, size_t ol)
{
    u32 blk;
    size_t done;
    done=0; blk=0;
    while(done<ol){
        u8 u[32],t[32],tmp[4];
        u32 i;
        int j;
        hmac_ctx c;
        size_t chunk;
        blk++;
        tmp[0]=(u8)(blk>>24);tmp[1]=(u8)(blk>>16);tmp[2]=(u8)(blk>>8);tmp[3]=(u8)blk;
        hmac_init(&c,pw,pl);
        hmac_update(&c,salt,sl); hmac_update(&c,tmp,4);
        hmac_final(&c,u); memcpy(t,u,32);
        for(i=1;i<iters;i++){
            hmac_sha256(pw,pl,u,32,u);
            for(j=0;j<32;j++) t[j]^=u[j];
        }
        chunk=ol-done; if(chunk>32)chunk=32;
        memcpy(out+done,t,chunk); done+=chunk;
        mem_wipe(u,32); mem_wipe(t,32);
    }
}

/* ================================================================
 * SALSA20/8 (used by scrypt)
 * ================================================================ */

#define SR(a,b) (((a)<<(b))|((a)>>(32-(b))))
static void salsa20_8(u8 *p)
{
    u32 x[16],B[16];
    int i;
    for(i=0;i<16;i++) B[i]=x[i]=load32_le(p+i*4);
    for(i=0;i<4;i++){
        x[4]^=SR(x[0]+x[12],7);  x[8]^=SR(x[4]+x[0],9);
        x[12]^=SR(x[8]+x[4],13); x[0]^=SR(x[12]+x[8],18);
        x[9]^=SR(x[5]+x[1],7);   x[13]^=SR(x[9]+x[5],9);
        x[1]^=SR(x[13]+x[9],13); x[5]^=SR(x[1]+x[13],18);
        x[14]^=SR(x[10]+x[6],7); x[2]^=SR(x[14]+x[10],9);
        x[6]^=SR(x[2]+x[14],13); x[10]^=SR(x[6]+x[2],18);
        x[3]^=SR(x[15]+x[11],7); x[7]^=SR(x[3]+x[15],9);
        x[11]^=SR(x[7]+x[3],13); x[15]^=SR(x[11]+x[7],18);
        x[1]^=SR(x[0]+x[3],7);   x[2]^=SR(x[1]+x[0],9);
        x[3]^=SR(x[2]+x[1],13);  x[0]^=SR(x[3]+x[2],18);
        x[6]^=SR(x[5]+x[4],7);   x[7]^=SR(x[6]+x[5],9);
        x[4]^=SR(x[7]+x[6],13);  x[5]^=SR(x[4]+x[7],18);
        x[11]^=SR(x[10]+x[9],7); x[8]^=SR(x[11]+x[10],9);
        x[9]^=SR(x[8]+x[11],13); x[10]^=SR(x[9]+x[8],18);
        x[12]^=SR(x[15]+x[14],7);x[13]^=SR(x[12]+x[15],9);
        x[14]^=SR(x[13]+x[12],13);x[15]^=SR(x[14]+x[13],18);
    }
    for(i=0;i<16;i++) store32_le(p+i*4,B[i]+x[i]);
}
#undef SR

/* scryptBlockMix: B = 2*r*64 bytes, r=8 -> 1024 bytes */
static void blockmix(u8 *B, u8 *Y, int r)
{
    u8 X[64];
    int i;
    int nb=2*r;
    memcpy(X,B+(nb-1)*64,64);
    for(i=0;i<nb;i++){
        int j;
        for(j=0;j<64;j++) X[j]^=B[i*64+j];
        salsa20_8(X); memcpy(Y+i*64,X,64);
    }
    for(i=0;i<r;i++) memcpy(B+i*64,    Y+2*i*64,    64);
    for(i=0;i<r;i++) memcpy(B+(r+i)*64,Y+(2*i+1)*64,64);
}

/* scrypt_romix_file: fallback cuando no hay RAM suficiente.
 * Usa un archivo temporal en disco para el array V.
 * Es correcto pero MUY lento en HDDs (accesos aleatorios). */
static int scrypt_romix_file(u8 *B, u64 N, int r, unsigned long bsz, u8 *X, u8 *Y)
{
    FILE *vf;
    u64 jraw;
    u8 *last;
    unsigned long j, k;
    unsigned long Nlo = u64_lo32(N);

    vf = tmpfile();
    if(!vf){
        fprintf(stderr,"error: could not create temporary file on disk\n");
        return -1;
    }
    fprintf(stderr,"[scrypt] using disk as temporary memory "
            "(this may take a very long time)...\n");

    /* Phase 1: fill V on disk sequentially */
    memcpy(X,B,bsz);
    for(j=0;j<Nlo;j++){
        if(fwrite(X,1,bsz,vf)!=bsz){ fclose(vf); return -1; }
        blockmix(X,Y,(int)r);
        if((j & 4095)==0)
            fprintf(stderr,"[scrypt] filling V: %lu/%lu\r",
                    (unsigned long)j, (unsigned long)Nlo);
    }
    fprintf(stderr,"\n[scrypt] V ready, mixing...\n");

    /* Phase 2: mix with random seeks into the file */
    for(j=0;j<Nlo;j++){
        last=X+(2*(unsigned long)r-1)*64;
        jraw.lo = load32_le(last);
        jraw.hi = load32_le(last+4);
        jraw = u64_and(jraw, u64_sub(N, u64_from32(1u)));
        if(fseek(vf, (long)(u64_lo32(jraw) * bsz), SEEK_SET)!=0){
            fclose(vf); return -1;
        }
        if(fread(Y,1,bsz,vf)!=bsz){ fclose(vf); return -1; }
        for(k=0;k<bsz;k++) X[k]^=Y[k];
        blockmix(X,Y,r);
        if((j & 4095)==0)
            fprintf(stderr,"[scrypt] mixing: %lu/%lu\r",
                    (unsigned long)j, (unsigned long)Nlo);
    }
    fprintf(stderr,"\n[scrypt] mix complete.\n");

    fclose(vf);
    memcpy(B,X,bsz);
    return 0;
}

static int scrypt_romix(u8 *B, u64 N, int r)
{
    unsigned long bsz;
    u8 *V,*Y,*X;
    u64 i;
    u64 jraw;
    u8 *last;
    unsigned long ioff, joff, k;
    int use_disk;
    /*
     * bsz = 128*r. For scrypt r=8, bsz=1024.
     */
    bsz = (unsigned long)(128*r);
    fprintf(stderr,"[scrypt] needs %lu KB of RAM...\n",
            (unsigned long)(u64_lo32(N) * bsz / 1024));
    V=(u8*)malloc(u64_lo32(N)*bsz);
    Y=(u8*)malloc(bsz);
    X=(u8*)malloc(bsz);
    use_disk=0;
    if(!V){
        free(V); V=NULL;
        fprintf(stderr,"[scrypt] not enough RAM, falling back to disk...\n");
        use_disk=1;
    }
    if(!Y||!X){
        free(V);free(Y);free(X);
        fprintf(stderr,"error: not enough memory even for temporary buffers\n");
        return -1;
    }
    if(use_disk){
        int ret=scrypt_romix_file(B,N,r,bsz,X,Y);
        mem_wipe(X,bsz); mem_wipe(Y,bsz);
        free(X); free(Y);
        return ret;
    }
    memcpy(X,B,bsz);
    i = u64_from32(0);
    while(u64_lt(i,N)){
        ioff = u64_lo32(i) * bsz;
        memcpy(V+ioff,X,bsz);
        blockmix(X,Y,r);
        i = u64_inc(i);
    }
    i = u64_from32(0);
    while(u64_lt(i,N)){
        last=X+(2*r-1)*64;
        jraw.lo = load32_le(last);
        jraw.hi = load32_le(last+4);
        jraw = u64_and(jraw, u64_sub(N, u64_from32(1u)));
        joff = u64_lo32(jraw) * bsz;
        for(k=0;k<bsz;k++) X[k]^=V[joff+k];
        blockmix(X,Y,r);
        i = u64_inc(i);
    }
    memcpy(B,X,bsz);
    mem_wipe(X,bsz);mem_wipe(Y,bsz);mem_wipe(V,u64_lo32(N)*bsz);
    free(X);free(Y);free(V);
    return 0;
}

static int scrypt_kdf(const u8 *pw, size_t pl, const u8 *salt, size_t sl,
                       int logN, u8 *out, size_t ol)
{
    u64 N;
    u8 B[1024];
    if(logN<1||logN>30) return -1;
    N = u64_shl(u64_from32(1u), logN);
    pbkdf2_sha256(pw,pl,salt,sl,1,B,1024);
    if(scrypt_romix(B,N,8)!=0) return -1;
    pbkdf2_sha256(pw,pl,B,1024,1,out,ol);
    mem_wipe(B,1024); return 0;
}

/* ================================================================
 * CHACHA20
 * ================================================================ */

typedef struct{u32 s[16];u8 ks[64];int pos;} cha_ctx;
#define QR(a,b,c,d) a+=b;d^=a;d=rotl32(d,16);c+=d;b^=c;b=rotl32(b,12);\
                    a+=b;d^=a;d=rotl32(d,8);c+=d;b^=c;b=rotl32(b,7)
static void cha_block(u32 *out, const u32 *in)
{
    u32 x[16];
    int i;
    memcpy(x,in,64);
    for(i=0;i<10;i++){
        QR(x[0],x[4],x[8],x[12]);QR(x[1],x[5],x[9],x[13]);
        QR(x[2],x[6],x[10],x[14]);QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]);QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8],x[13]);QR(x[3],x[4],x[9],x[14]);
    }
    for(i=0;i<16;i++) out[i]=x[i]+in[i];
}
static void cha_init(cha_ctx *ctx, const u8 *key, const u8 *nonce, u32 ctr)
{
    ctx->s[0]=0x61707865UL;ctx->s[1]=0x3320646eUL;
    ctx->s[2]=0x79622d32UL;ctx->s[3]=0x6b206574UL;
    ctx->s[4]=load32_le(key);ctx->s[5]=load32_le(key+4);
    ctx->s[6]=load32_le(key+8);ctx->s[7]=load32_le(key+12);
    ctx->s[8]=load32_le(key+16);ctx->s[9]=load32_le(key+20);
    ctx->s[10]=load32_le(key+24);ctx->s[11]=load32_le(key+28);
    ctx->s[12]=ctr;
    ctx->s[13]=load32_le(nonce);ctx->s[14]=load32_le(nonce+4);ctx->s[15]=load32_le(nonce+8);
    ctx->pos=64;
}
static void cha_xor(cha_ctx *ctx, const u8 *in, u8 *out, size_t n)
{
    size_t i;
    for(i=0;i<n;i++){
        if(ctx->pos==64){
            u32 bl[16];
            int j;
            cha_block(bl,ctx->s);
            for(j=0;j<16;j++) store32_le(ctx->ks+j*4,bl[j]);
            ctx->s[12]++; ctx->pos=0;
        }
        out[i]=in[i]^ctx->ks[ctx->pos++];
    }
}

/* ================================================================
 * POLY1305
 * ================================================================ */

typedef struct{u32 r[5],h[5],pad[4];u8 buf[16];int left;} p1305_ctx;

static void p1305_init(p1305_ctx *ctx, const u8 *key)
{
    ctx->r[0]= (load32_le(key   ))     &0x3ffffff;
    ctx->r[1]= (load32_le(key+3)>>2)   &0x3ffff03;
    ctx->r[2]= (load32_le(key+6)>>4)   &0x3ffc0ff;
    ctx->r[3]= (load32_le(key+9)>>6)   &0x3f03fff;
    ctx->r[4]= (load32_le(key+12)>>8)  &0x00fffff;
    ctx->pad[0]=load32_le(key+16);ctx->pad[1]=load32_le(key+20);
    ctx->pad[2]=load32_le(key+24);ctx->pad[3]=load32_le(key+28);
    ctx->h[0]=ctx->h[1]=ctx->h[2]=ctx->h[3]=ctx->h[4]=0;
    ctx->left=0;
}
static void p1305_block(p1305_ctx *ctx, const u8 *m, int hi)
{
    u32 r0,r1,r2,r3,r4,s1,s2,s3,s4,h0,h1,h2,h3,h4,c;
    u64 d0,d1,d2,d3,d4;
    r0=ctx->r[0];r1=ctx->r[1];r2=ctx->r[2];r3=ctx->r[3];r4=ctx->r[4];
    s1=r1*5;s2=r2*5;s3=r3*5;s4=r4*5;
    h0=ctx->h[0];h1=ctx->h[1];h2=ctx->h[2];h3=ctx->h[3];h4=ctx->h[4];
    h0+=(load32_le(m))&0x3ffffff;
    h1+=(load32_le(m+3)>>2)&0x3ffffff;
    h2+=(load32_le(m+6)>>4)&0x3ffffff;
    h3+=(load32_le(m+9)>>6)&0x3ffffff;
    h4+=(load32_le(m+12)>>8)|((u32)hi<<24);
    /* d = h*r using u64 emulation */
    d0=u64_add(u64_add(u64_add(u64_add(
        u64_mul(u64_from32(h0),u64_from32(r0)),
        u64_mul(u64_from32(h1),u64_from32(s4))),
        u64_mul(u64_from32(h2),u64_from32(s3))),
        u64_mul(u64_from32(h3),u64_from32(s2))),
        u64_mul(u64_from32(h4),u64_from32(s1)));
    d1=u64_add(u64_add(u64_add(u64_add(
        u64_mul(u64_from32(h0),u64_from32(r1)),
        u64_mul(u64_from32(h1),u64_from32(r0))),
        u64_mul(u64_from32(h2),u64_from32(s4))),
        u64_mul(u64_from32(h3),u64_from32(s3))),
        u64_mul(u64_from32(h4),u64_from32(s2)));
    d2=u64_add(u64_add(u64_add(u64_add(
        u64_mul(u64_from32(h0),u64_from32(r2)),
        u64_mul(u64_from32(h1),u64_from32(r1))),
        u64_mul(u64_from32(h2),u64_from32(r0))),
        u64_mul(u64_from32(h3),u64_from32(s4))),
        u64_mul(u64_from32(h4),u64_from32(s3)));
    d3=u64_add(u64_add(u64_add(u64_add(
        u64_mul(u64_from32(h0),u64_from32(r3)),
        u64_mul(u64_from32(h1),u64_from32(r2))),
        u64_mul(u64_from32(h2),u64_from32(r1))),
        u64_mul(u64_from32(h3),u64_from32(r0))),
        u64_mul(u64_from32(h4),u64_from32(s4)));
    d4=u64_add(u64_add(u64_add(u64_add(
        u64_mul(u64_from32(h0),u64_from32(r4)),
        u64_mul(u64_from32(h1),u64_from32(r3))),
        u64_mul(u64_from32(h2),u64_from32(r2))),
        u64_mul(u64_from32(h3),u64_from32(r1))),
        u64_mul(u64_from32(h4),u64_from32(r0)));
    /* carry reduction */
    c=u64_lo32(u64_shr(d0,26)); h0=u64_lo32(d0)&0x3ffffff; d1=u64_add(d1,u64_from32(c));
    c=u64_lo32(u64_shr(d1,26)); h1=u64_lo32(d1)&0x3ffffff; d2=u64_add(d2,u64_from32(c));
    c=u64_lo32(u64_shr(d2,26)); h2=u64_lo32(d2)&0x3ffffff; d3=u64_add(d3,u64_from32(c));
    c=u64_lo32(u64_shr(d3,26)); h3=u64_lo32(d3)&0x3ffffff; d4=u64_add(d4,u64_from32(c));
    c=u64_lo32(u64_shr(d4,26)); h4=u64_lo32(d4)&0x3ffffff; h0+=c*5;
    c=h0>>26;h0&=0x3ffffff;h1+=c;
    ctx->h[0]=h0;ctx->h[1]=h1;ctx->h[2]=h2;ctx->h[3]=h3;ctx->h[4]=h4;
}
static void p1305_update(p1305_ctx *ctx, const u8 *m, size_t n)
{
    size_t want;
    if(ctx->left){
        want=(size_t)(16-ctx->left); if(want>n)want=n;
        memcpy(ctx->buf+ctx->left,m,want);
        ctx->left+=(int)want; m+=want; n-=want;
        if(ctx->left<16) return;
        p1305_block(ctx,ctx->buf,1); ctx->left=0;
    }
    while(n>=16){p1305_block(ctx,m,1);m+=16;n-=16;}
    if(n){memcpy(ctx->buf,m,n);ctx->left=(int)n;}
}
static void p1305_final(p1305_ctx *ctx, u8 *mac)
{
    u32 h0,h1,h2,h3,h4,g0,g1,g2,g3,g4,c,mask;
    u64 f;
    if(ctx->left){
        ctx->buf[ctx->left]=1;
        memset(ctx->buf+ctx->left+1,0,(size_t)(16-ctx->left-1));
        p1305_block(ctx,ctx->buf,0);
    }
    h0=ctx->h[0];h1=ctx->h[1];h2=ctx->h[2];h3=ctx->h[3];h4=ctx->h[4];
    c=h1>>26;h1&=0x3ffffff;h2+=c;c=h2>>26;h2&=0x3ffffff;h3+=c;
    c=h3>>26;h3&=0x3ffffff;h4+=c;c=h4>>26;h4&=0x3ffffff;h0+=c*5;
    c=h0>>26;h0&=0x3ffffff;h1+=c;
    g0=h0+5;c=g0>>26;g0&=0x3ffffff;g1=h1+c;c=g1>>26;g1&=0x3ffffff;
    g2=h2+c;c=g2>>26;g2&=0x3ffffff;g3=h3+c;c=g3>>26;g3&=0x3ffffff;
    g4=h4+c-(1<<26);
    mask=(g4>>31)-1;
    g0&=mask;g1&=mask;g2&=mask;g3&=mask;g4&=mask;mask=~mask;
    h0=(h0&mask)|g0;h1=(h1&mask)|g1;h2=(h2&mask)|g2;h3=(h3&mask)|g3;h4=(h4&mask)|g4;
    h0=((h0    )|(h1<<26))&0xffffffffu;
    h1=((h1>> 6)|(h2<<20))&0xffffffffu;
    h2=((h2>>12)|(h3<<14))&0xffffffffu;
    h3=((h3>>18)|(h4<< 8))&0xffffffffu;
    f=u64_add(u64_from32(h0),u64_from32(ctx->pad[0]));
    store32_le(mac+ 0, u64_lo32(f));
    f=u64_add(u64_add(u64_from32(h1),u64_from32(ctx->pad[1])),u64_from32(u64_hi32(f)));
    store32_le(mac+ 4, u64_lo32(f));
    f=u64_add(u64_add(u64_from32(h2),u64_from32(ctx->pad[2])),u64_from32(u64_hi32(f)));
    store32_le(mac+ 8, u64_lo32(f));
    f=u64_add(u64_add(u64_from32(h3),u64_from32(ctx->pad[3])),u64_from32(u64_hi32(f)));
    store32_le(mac+12, u64_lo32(f));
    mem_wipe(ctx,sizeof(*ctx));
}

/* ================================================================
 * CHACHA20-POLY1305 AEAD (RFC 8439)
 * ================================================================ */

static void cp_mac_segment(p1305_ctx *mac, const u8 *d, size_t n)
{
    static const u8 z[16]={0};
    p1305_update(mac,d,n);
    if(n%16) p1305_update(mac,z,16-(n%16));
}

static void cp_seal(const u8 *key, const u8 *nonce,
                    const u8 *aad, size_t al,
                    const u8 *plain, size_t pl, u8 *out)
{
    cha_ctx s;
    p1305_ctx mac;
    u8 otk[64],zeros[64],lens[16];
    memset(zeros,0,64);
    cha_init(&s,key,nonce,0); cha_xor(&s,zeros,otk,64);
    cha_init(&s,key,nonce,1); cha_xor(&s,plain,out,pl);
    p1305_init(&mac,otk);
    cp_mac_segment(&mac,aad,al);
    cp_mac_segment(&mac,out,pl);
    store64_le(lens+0, u64_from32((u32)al));
    store64_le(lens+8, u64_from32((u32)pl));
    p1305_update(&mac,lens,16); p1305_final(&mac,out+pl);
    mem_wipe(&s,sizeof(s)); mem_wipe(otk,64);
}

static int cp_open(const u8 *key, const u8 *nonce,
                   const u8 *aad, size_t al,
                   const u8 *cipher, size_t cl, u8 *out)
{
    cha_ctx s;
    p1305_ctx mac;
    u8 otk[64],zeros[64],lens[16],tag[16];
    size_t pl;
    int diff,i;
    if(verbose) fprintf(stderr,"[AEAD] cp_open cl=%u al=%u\n",(unsigned)cl,(unsigned)al);
    dbg_hex("[AEAD] key", key, 32);
    dbg_hex("[AEAD] nonce", nonce, 12);
    if(cl<16){ if(verbose) fprintf(stderr,"[AEAD] ERROR: cl<16\n"); return -1; }
    pl=cl-16;
    dbg_hex("[AEAD] cipher (no tag)", cipher, (int)pl);
    dbg_hex("[AEAD] expected tag", cipher+pl, 16);
    memset(zeros,0,64);
    cha_init(&s,key,nonce,0); cha_xor(&s,zeros,otk,64);
    dbg_hex("[AEAD] OTK (Poly1305 key)", otk, 32);
    p1305_init(&mac,otk);
    cp_mac_segment(&mac,aad,al);
    cp_mac_segment(&mac,cipher,pl);
    store64_le(lens+0, u64_from32((u32)al));
    store64_le(lens+8, u64_from32((u32)pl));
    p1305_update(&mac,lens,16); p1305_final(&mac,tag);
    dbg_hex("[AEAD] computed tag", tag, 16);
    diff=0; for(i=0;i<16;i++) diff|=(tag[i]^cipher[pl+i]);
    if(verbose){
        if(diff) fprintf(stderr,"[AEAD] FAIL: tags do not match\n");
        else     fprintf(stderr,"[AEAD] OK: tags match\n");
    }
    mem_wipe(otk,64); mem_wipe(tag,16);
    if(diff) return -1;
    cha_init(&s,key,nonce,1); cha_xor(&s,cipher,out,pl);
    mem_wipe(&s,sizeof(s)); return 0;
}

/* ================================================================
 * CURVE25519 / X25519
 * Based on TweetNaCl (public domain)
 * GF(2^255-19) with 16 limbs of 16-bit signed values (stored in s64)
 * ================================================================ */

typedef s64 gf[16];

static void gf0(gf r)
{
    int i;
    for(i=0;i<16;i++){r[i].lo=0;r[i].hi=0;}
}
static void gf1(gf r)
{
    gf0(r); r[0]=s64_one();
}
static void gfcp(gf r, const gf a)
{
    int i;
    for(i=0;i<16;i++) r[i]=a[i];
}
static void gfadd(gf r, const gf a, const gf b)
{
    int i;
    for(i=0;i<16;i++) r[i]=s64_add(a[i],b[i]);
}
static void gfsub(gf r, const gf a, const gf b)
{
    int i;
    for(i=0;i<16;i++) r[i]=s64_sub(a[i],b[i]);
}

static void gfcar(gf r)
{
    int i;
    s64 c;
    for(i=0;i<16;i++){
        /* r[i] += (1<<16) */
        r[i] = s64_add(r[i], s64_shl(s64_one(), 16));
        /* c = r[i] >> 16 */
        c = s64_sar(r[i], 16);
        /* r[(i+1)*(i<15)] += c - 1 + 37*(c-1)*(i==15) */
        if(i < 15){
            r[i+1] = s64_add(r[i+1], s64_sub(c, s64_one()));
        } else {
            /* i==15: r[0] += 37*(c-1) */
            r[0] = s64_add(r[0], s64_mul_int(s64_sub(c, s64_one()), 37));
        }
        /* r[i] -= c << 16 */
        r[i] = s64_sub(r[i], s64_shl(c, 16));
    }
}

static void gfsel(gf p, gf q, int b)
{
    s64 t, c;
    int i;
    /* c = ~(b-1): if b==1 then c=0xFFFF...FFFF, if b==0 then c=0 */
    c = s64_not(s64_from_int(b-1));
    for(i=0;i<16;i++){
        t = s64_and(c, s64_xor(p[i], q[i]));
        p[i] = s64_xor(p[i], t);
        q[i] = s64_xor(q[i], t);
    }
}

static void gfmul(gf r, const gf a, const gf b)
{
    s64 t[31];
    int i,j;
    for(i=0;i<31;i++){t[i].lo=0;t[i].hi=0;}
    for(i=0;i<16;i++)
        for(j=0;j<16;j++)
            t[i+j] = s64_add(t[i+j], s64_mul(a[i], b[j]));
    for(i=0;i<15;i++)
        t[i] = s64_add(t[i], s64_mul_int(t[i+16], 38));
    for(i=0;i<15;i++){
        t[i+1] = s64_add(t[i+1], s64_sar(t[i],16));
        t[i] = s64_and(t[i], s64_from_int(0xffff));
    }
    t[0] = s64_add(t[0], s64_mul_int(s64_sar(t[15],16), 38));
    t[15] = s64_and(t[15], s64_from_int(0xffff));
    for(i=0;i<15;i++){
        t[i+1] = s64_add(t[i+1], s64_sar(t[i],16));
        t[i] = s64_and(t[i], s64_from_int(0xffff));
    }
    for(i=0;i<16;i++) r[i]=t[i];
}

static void gfsqr(gf r, const gf a)
{
    gfmul(r,a,a);
}

static void gfpack(u8 *o, const gf n)
{
    gf m,t;
    int i,j,b;
    gfcp(t,n); gfcar(t); gfcar(t); gfcar(t);
    for(j=0;j<2;j++){
        m[0] = s64_sub(t[0], s64_from_int(0xffed));
        for(i=1;i<15;i++){
            s64 borrow;
            borrow = s64_and(s64_sar(m[i-1],16), s64_one());
            m[i] = s64_sub(s64_sub(t[i], s64_from_int(0xffff)), borrow);
            m[i-1] = s64_and(m[i-1], s64_from_int(0xffff));
        }
        {
            s64 borrow;
            borrow = s64_and(s64_sar(m[14],16), s64_one());
            m[15] = s64_sub(s64_sub(t[15], s64_from_int(0x7fff)), borrow);
        }
        b = s64_to_int(s64_and(s64_sar(m[15],16), s64_one()));
        m[14] = s64_and(m[14], s64_from_int(0xffff));
        gfsel(t,m,1-b);
    }
    for(i=0;i<16;i++){
        o[2*i]  = (u8)(s64_lo32(t[i]) & 0xff);
        o[2*i+1]= (u8)((s64_lo32(t[i])>>8) & 0xff);
    }
}

static void gfunpack(gf r, const u8 *n)
{
    int i;
    for(i=0;i<16;i++){
        u32 lo = (u32)n[2*i];
        u32 hi_byte = (u32)n[2*i+1];
        r[i] = s64_from32(lo | (hi_byte << 8));
    }
    r[15] = s64_and(r[15], s64_from_int(0x7fff));
}

static void gfinv(gf r, const gf a)
{
    gf t,c;
    int i;
    gfcp(c,a);
    for(i=253;i>=0;i--){
        gfsqr(t,c);
        if(i!=2&&i!=4) gfmul(c,t,a); else gfcp(c,t);
    }
    gfcp(r,c);
}

/* X25519 using RFC 7748 Montgomery ladder with TweetNaCl GF */
static void x25519(u8 *out, const u8 *scalar, const u8 *point)
{
    u8 e[32];
    gf x1,x2,z2,x3,z3,A,AA,B,BB,E,C,D,DA,CB,tmp;
    static const gf a24 = {
        {0xDB41,0},{1,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},
        {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}
    };
    int swap,i,bit;

    memcpy(e,scalar,32);
    e[0]&=248; e[31]&=127; e[31]|=64;

    gfunpack(x1,point);
    gf1(x2);
    gf0(z2);
    gfcp(x3,x1);
    gf1(z3);

    swap=0;
    for(i=254;i>=0;i--){
        bit=(e[i>>3]>>(i&7))&1;
        swap^=bit;
        gfsel(x2,x3,swap);
        gfsel(z2,z3,swap);
        swap=bit;

        gfadd(A,x2,z2);   gfsqr(AA,A);
        gfsub(B,x2,z2);   gfsqr(BB,B);
        gfsub(E,AA,BB);
        gfadd(C,x3,z3);
        gfsub(D,x3,z3);
        gfmul(DA,D,A);
        gfmul(CB,C,B);
        gfadd(tmp,DA,CB); gfsqr(x3,tmp);
        gfsub(tmp,DA,CB); gfsqr(z3,tmp);
        gfmul(z3,z3,x1);
        gfmul(x2,AA,BB);
        gfmul(tmp,a24,E);
        gfadd(tmp,tmp,AA);
        gfmul(z2,E,tmp);
    }
    gfsel(x2,x3,swap);
    gfsel(z2,z3,swap);
    gfinv(z2,z2);
    gfmul(x2,x2,z2);
    gfpack(out,x2);
}

static void x25519_pubkey(u8 *pub, const u8 *priv)
{
    static const u8 bp[32]={9};
    x25519(pub,priv,bp);
}

/* ================================================================
 * RANDOM
 * ================================================================ */

static int rand_bytes(u8 *buf, size_t n)
{
    size_t i;
    for(i=0;i<n;i++) buf[i]=(u8)(rand()&0xff);
    return 0;
}

/* ================================================================
 * BASE64 without padding (RawStdEncoding)
 * ================================================================ */

static const char B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64enc(const u8 *src, size_t sl, char *dst)
{
    size_t i;
    char *p=dst;
    for(i=0;i+3<=sl;i+=3){
        u32 v=((u32)src[i]<<16)|((u32)src[i+1]<<8)|src[i+2];
        *p++=B64[(v>>18)&63];*p++=B64[(v>>12)&63];*p++=B64[(v>>6)&63];*p++=B64[v&63];
    }
    if(i<sl){
        u32 v=(u32)src[i]<<16; if(i+1<sl) v|=(u32)src[i+1]<<8;
        *p++=B64[(v>>18)&63]; *p++=B64[(v>>12)&63];
        if(i+1<sl) *p++=B64[(v>>6)&63];
    }
    *p='\0';
}

static int b64dec(const char *src, size_t sl, u8 *dst)
{
    static const int T[256]={
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    size_t i;
    int out=0,bits=0;
    u32 acc=0;
    for(i=0;i<sl;i++){
        int v=T[(unsigned char)src[i]];
        if(v<0) return -1;
        acc=(acc<<6)|(u32)v; bits+=6;
        if(bits>=8){bits-=8;dst[out++]=(u8)(acc>>bits);}
    }
    return out;
}

/* ================================================================
 * BECH32
 * ================================================================ */

static const char BC[]="qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static u32 bech32_pm(const u8 *v, size_t n)
{
    static const u32 G[5]={0x3b6a57b2UL,0x26508e6dUL,0x1ea119faUL,0x3d4233ddUL,0x2a1462b3UL};
    u32 c=1;
    size_t i;
    int j;
    for(i=0;i<n;i++){
        u8 top=(u8)(c>>25);
        c=((c&0x1ffffff)<<5)^v[i];
        for(j=0;j<5;j++) if((top>>j)&1) c^=G[j];
    }
    return c;
}

static int bech32_encode(const char *hrp, const u8 *data, size_t dl, char *out)
{
    size_t hl=strlen(hrp), i;
    u8 exp[256]; size_t el=0;
    u8 d5[256];  size_t d5l=0;
    u8 all[512]; size_t al;
    u32 chk;
    char *p=out;
    u32 acc=0;
    int bits=0;

    for(i=0;i<hl;i++) exp[el++]=(u8)(ascii_tolower((unsigned char)hrp[i])>>5);
    exp[el++]=0;
    for(i=0;i<hl;i++) exp[el++]=(u8)(ascii_tolower((unsigned char)hrp[i])&31);

    for(i=0;i<dl;i++){
        acc=(acc<<8)|data[i]; bits+=8;
        while(bits>=5){bits-=5;d5[d5l++]=(u8)((acc>>bits)&31);}
    }
    if(bits) d5[d5l++]=(u8)((acc<<(5-bits))&31);

    al=0;
    memcpy(all+al,exp,el); al+=el;
    memcpy(all+al,d5,d5l); al+=d5l;
    memset(all+al,0,6); al+=6;
    chk=bech32_pm(all,al)^1;

    memcpy(p,hrp,hl); p+=hl; *p++='1';
    for(i=0;i<d5l;i++) *p++=BC[d5[i]];
    for(i=0;i<6;i++) *p++=BC[(chk>>(5*(5-(int)i)))&31];
    *p='\0'; return 0;
}

static int bech32_decode(const char *str, char *hrp, u8 *data, size_t *dl)
{
    size_t sl=strlen(str), i;
    int pos=-1;
    u8 exp[256]; size_t el=0;
    u8 d5[256];  size_t d5l=0;
    u8 all[512]; size_t al;
    u32 chk;
    u32 acc=0;
    int bits=0;

    for(i=0;i<sl;i++) if(str[i]=='1') pos=(int)i;
    if(pos<1||(size_t)pos+7>sl) return -1;

    memcpy(hrp,str,(size_t)pos); hrp[pos]='\0';
    {
        size_t hl;
        hl=(size_t)pos;
        for(i=0;i<hl;i++) exp[el++]=(u8)(hrp[i]>>5);
        exp[el++]=0;
        for(i=0;i<hl;i++) exp[el++]=(u8)(hrp[i]&31);
    }

    for(i=(size_t)pos+1;i<sl;i++){
        int ci;
        u8 v=255;
        int lo=ascii_tolower((unsigned char)str[i]);
        for(ci=0;ci<32;ci++) if(BC[ci]==lo){v=(u8)ci;break;}
        if(v==255) return -1;
        d5[d5l++]=v;
    }
    if(d5l<6) return -1;

    al=0;
    memcpy(all+al,exp,el); al+=el;
    memcpy(all+al,d5,d5l); al+=d5l;
    chk=bech32_pm(all,al);
    if(chk!=1) return -1;

    d5l-=6;
    *dl=0; acc=0; bits=0;
    for(i=0;i<d5l;i++){
        acc=(acc<<5)|d5[i]; bits+=5;
        if(bits>=8){bits-=8;data[(*dl)++]=(u8)((acc>>bits)&0xff);}
    }
    return 0;
}

/* ================================================================
 * AGE HEADER
 * ================================================================ */

#define MAX_STANZAS  8
#define MAX_ARGS     4
#define MAX_ARG      256
#define MAX_BODY     512
#define FILEKEY_SZ   16
#define COLS         64
#define BYTES_PL     48

typedef struct {
    char type[64];
    char args[MAX_ARGS][MAX_ARG];
    int  nargs;
    u8   body[MAX_BODY];
    int  blen;
} stanza;

typedef struct {
    stanza s[MAX_STANZAS];
    int    ns;
    u8     mac[32];
} age_hdr;

static int hdr_to_buf(const age_hdr *hdr, u8 *buf, size_t bufsize)
{
    int n=0,i,j;
    char tmp[512];
    int r;
    r=sprintf(tmp,"age-encryption.org/v1\n");
    if((size_t)(n+r)>bufsize) return -1;
    memcpy(buf+n,tmp,(size_t)r); n+=r;
    for(i=0;i<hdr->ns;i++){
        const stanza *s=&hdr->s[i];
        char enc[MAX_BODY*2];
        size_t enclen;
        size_t pos;        r=sprintf(tmp,"-> %s",s->type);
        if((size_t)(n+r)>bufsize) return -1;
        memcpy(buf+n,tmp,(size_t)r); n+=r;
        for(j=0;j<s->nargs;j++){
            r=sprintf(tmp," %s",s->args[j]);
            if((size_t)(n+r)>bufsize) return -1;
            memcpy(buf+n,tmp,(size_t)r); n+=r;
        }
        buf[n++]='\n';
        b64enc(s->body,(size_t)s->blen,enc);
        enclen=strlen(enc);
        pos=0;
        while(pos<enclen){
            size_t chunk=(enclen-pos>(size_t)COLS)?(size_t)COLS:(enclen-pos);
            if((size_t)(n+(int)chunk+1)>bufsize) return -1;
            memcpy(buf+n,enc+pos,chunk); n+=(int)chunk;
            buf[n++]='\n'; pos+=chunk;
        }
        if(enclen==0||enclen%COLS==0){
            if((size_t)(n+1)>bufsize) return -1;
            buf[n++]='\n';
        }
    }
    r=sprintf(tmp,"---");
    if((size_t)(n+r)>bufsize) return -1;
    memcpy(buf+n,tmp,(size_t)r); n+=r;
    return n;
}

static void write_hdr(FILE *fp, const age_hdr *hdr)
{
    u8 buf[65536];
    int n;
    char mac_b64[64];
    n=hdr_to_buf(hdr,buf,sizeof(buf));
    if(n<0){fprintf(stderr,"error: header too large\n");return;}
    fwrite(buf,1,(size_t)n,fp);
    b64enc(hdr->mac,32,mac_b64);
    fprintf(fp," %s\n",mac_b64);
}

static int read_line(FILE *fp, char *buf, int max)
{
    int c,n=0;
    while((c=fgetc(fp))!=EOF){
        if(c=='\n'){
            /* quitar \r si lo hay (archivos creados en Unix abiertos en Windows) */
            if(n>0&&buf[n-1]=='\r') n--;
            buf[n]='\0';
            if(verbose) fprintf(stderr,"[LINE] len=%d  \"%s\"\n",n,buf);
            return n;
        }
        if(n<max-1) buf[n++]=(char)c;
    }
    if(n>0){buf[n]='\0';if(verbose) fprintf(stderr,"[LINE/EOF] len=%d  \"%s\"\n",n,buf);return n;}
    if(verbose) fprintf(stderr,"[LINE] EOF\n");
    return -1;
}

static int parse_hdr(FILE *fp, age_hdr *hdr)
{
    char line[512];
    hdr->ns=0;
    if(read_line(fp,line,sizeof(line))<0) return -1;
    if(strcmp(line,"age-encryption.org/v1")!=0){
        fprintf(stderr,"error: invalid age format\n"); return -1;
    }
    for(;;){
        if(read_line(fp,line,sizeof(line))<0) return -1;
        if(strncmp(line,"---",3)==0){
            u8 tmp[64];
            int dl;
            char *mac_b64=line+4;
            dl=b64dec(mac_b64,strlen(mac_b64),tmp);
            if(dl!=32){fprintf(stderr,"error: invalid MAC\n");return -1;}
            memcpy(hdr->mac,tmp,32); break;
        }
        if(strncmp(line,"-> ",3)==0){
            stanza *s;
            char linecopy[512];
            char *tok;
            int bodylen=0;
            if(hdr->ns>=MAX_STANZAS) return -1;
            s=&hdr->s[hdr->ns++]; s->nargs=0;
            strncpy(linecopy,line+3,sizeof(linecopy)-1);
            linecopy[sizeof(linecopy)-1]='\0';
            tok=strtok(linecopy," ");
            if(!tok) return -1;
            strncpy(s->type,tok,63); s->type[63]='\0';
            while((tok=strtok(NULL," "))!=NULL&&s->nargs<MAX_ARGS){
                strncpy(s->args[s->nargs],tok,MAX_ARG-1);
                s->args[s->nargs][MAX_ARG-1]='\0';
                s->nargs++;
            }
            for(;;){
                u8 dec[BYTES_PL+4];
                int dl, rl;
                char bline[128];                rl=read_line(fp,bline,sizeof(bline));
                if(rl<0) return -1;
                dl=b64dec(bline,(size_t)rl,dec);
                if(dl<0) return -1;
                if(bodylen+dl>MAX_BODY) return -1;
                memcpy(s->body+bodylen,dec,(size_t)dl);
                bodylen+=dl;
                if(dl<BYTES_PL) break;
            }
            s->blen=bodylen;
        }
    }
    return 0;
}

/* ================================================================
 * AGE ENCRYPT
 * ================================================================ */

static int age_encrypt(FILE *fin, FILE *fout, const u8 *fk, age_hdr *hdr)
{
    u8 hdrbuf[65536];
    int hlen;
    u8 hmac_key[32];
    u8 snonce[16], skey[32];
    u8 cnonce[12], plain[65536], cipher[65536+16];
    u64 idx;
    int last;

    hkdf_sha256(fk,FILEKEY_SZ, NULL,0, (u8*)"header",6, hmac_key,32);
    hlen=hdr_to_buf(hdr,hdrbuf,sizeof(hdrbuf));
    if(hlen<0) return -1;
    hmac_sha256(hmac_key,32, hdrbuf,(size_t)hlen, hdr->mac);
    mem_wipe(hmac_key,32);

    write_hdr(fout,hdr);

    if(rand_bytes(snonce,16)!=0) return -1;
    fwrite(snonce,1,16,fout);
    hkdf_sha256(fk,FILEKEY_SZ, snonce,16, (u8*)"payload",7, skey,32);

    memset(cnonce,0,12);
    idx = u64_from32(0);
    last=0;
    while(!last){
        size_t nr;
        int peek;
        nr=fread(plain,1,65536,fin);
        if(nr<65536) last=1;
        else{peek=fgetc(fin);if(peek==EOF)last=1;else ungetc(peek,fin);}
        cnonce[0]=0;cnonce[1]=0;cnonce[2]=0;
        cnonce[3]=(u8)(idx.hi>>24);cnonce[4]=(u8)(idx.hi>>16);
        cnonce[5]=(u8)(idx.hi>>8); cnonce[6]=(u8)(idx.hi);
        cnonce[7]=(u8)(idx.lo>>24);cnonce[8]=(u8)(idx.lo>>16);
        cnonce[9]=(u8)(idx.lo>>8); cnonce[10]=(u8)(idx.lo);
        cnonce[11]=last?0x01:0x00;
        cp_seal(skey,cnonce, NULL,0, plain,nr, cipher);
        fwrite(cipher,1,nr+16,fout);
        idx = u64_inc(idx);
    }
    mem_wipe(skey,32); mem_wipe(plain,65536);
    return 0;
}

/* ================================================================
 * AGE DECRYPT
 * ================================================================ */

static int age_decrypt(FILE *fin, FILE *fout, const u8 *fk)
{
    u8 snonce[16], skey[32], cnonce[12];
    u8 cipher[65536+16], plain[65536];
    u64 idx;
    if(fread(snonce,1,16,fin)!=16){fprintf(stderr,"error: truncated nonce\n");return -1;}
    hkdf_sha256(fk,FILEKEY_SZ, snonce,16, (u8*)"payload",7, skey,32);
    idx = u64_from32(0);
    for(;;){
        size_t nr;
        int last,ret;
        nr=fread(cipher,1,65536+16,fin);
        last=0;
        if(nr<16&&nr>0){fprintf(stderr,"error: invalid chunk\n");mem_wipe(skey,32);return -1;}
        if(nr==0) break;
        cnonce[0]=0;cnonce[1]=0;cnonce[2]=0;
        cnonce[3]=(u8)(idx.hi>>24);cnonce[4]=(u8)(idx.hi>>16);
        cnonce[5]=(u8)(idx.hi>>8); cnonce[6]=(u8)(idx.hi);
        cnonce[7]=(u8)(idx.lo>>24);cnonce[8]=(u8)(idx.lo>>16);
        cnonce[9]=(u8)(idx.lo>>8); cnonce[10]=(u8)(idx.lo);
        cnonce[11]=0x00;
        ret=cp_open(skey,cnonce, NULL,0, cipher,nr, plain);
        if(ret!=0){
            cnonce[11]=0x01;
            ret=cp_open(skey,cnonce, NULL,0, cipher,nr, plain);
            if(ret!=0){
                fprintf(stderr,"error: authentication failed on chunk\n");
                mem_wipe(skey,32); return -1;
            }
            last=1;
        } else if(nr<(65536+16)){
            last=1;
        }
        fwrite(plain,1,nr-16,fout);
        idx = u64_inc(idx);
        if(last) break;
    }
    mem_wipe(skey,32); mem_wipe(plain,65536);
    return 0;
}

/* ================================================================
 * AGE X25519 WRAP/UNWRAP
 * ================================================================ */

static int x25519_wrap(const u8 *rpub, const u8 *fk, stanza *s)
{
    u8 epriv[32],epub[32],shared[32],salt[64],wk[32],nonce[12];
    if(rand_bytes(epriv,32)!=0) return -1;
    x25519_pubkey(epub,epriv);
    x25519(shared,epriv,rpub);
    memcpy(salt,epub,32); memcpy(salt+32,rpub,32);
    hkdf_sha256(shared,32, salt,64, (u8*)"age-encryption.org/v1/X25519",28, wk,32);
    memset(nonce,0,12);
    strcpy(s->type,"X25519"); s->nargs=1;
    b64enc(epub,32,s->args[0]);
    cp_seal(wk,nonce, NULL,0, fk,FILEKEY_SZ, s->body);
    s->blen=FILEKEY_SZ+16;
    mem_wipe(epriv,32); mem_wipe(shared,32); mem_wipe(wk,32);
    return 0;
}

static int x25519_unwrap(const u8 *priv, const u8 *pub, const stanza *s, u8 *fk)
{
    u8 epub[32],shared[32],salt[64],wk[32],nonce[12];
    int dl;
    if(verbose) fprintf(stderr,"[X25519_UNWRAP] --- begin ---\n");
    dbg_str("[X25519_UNWRAP] stanza.type", s->type);
    if(strcmp(s->type,"X25519")!=0||s->nargs<1){
        if(verbose) fprintf(stderr,"[X25519_UNWRAP] wrong type or no args\n"); return -1;}
    dbg_str("[X25519_UNWRAP] stanza.args[0] (epub b64)", s->args[0]);
    dl=b64dec(s->args[0],strlen(s->args[0]),epub);
    if(verbose) fprintf(stderr,"[X25519_UNWRAP] b64dec epub -> %d bytes\n",dl);
    if(dl!=32){ if(verbose) fprintf(stderr,"[X25519_UNWRAP] ERROR: epub is not 32 bytes\n"); return -1; }
    dbg_hex("[X25519_UNWRAP] epub", epub, 32);
    dbg_hex("[X25519_UNWRAP] priv", priv, 32);
    dbg_hex("[X25519_UNWRAP] pub (derived from priv)", pub, 32);
    x25519(shared,priv,epub);
    dbg_hex("[X25519_UNWRAP] shared secret", shared, 32);
    memcpy(salt,epub,32); memcpy(salt+32,pub,32);
    dbg_hex("[X25519_UNWRAP] salt (epub||pub)", salt, 64);
    hkdf_sha256(shared,32, salt,64, (u8*)"age-encryption.org/v1/X25519",28, wk,32);
    dbg_hex("[X25519_UNWRAP] wrap key (wk)", wk, 32);
    dbg_hex("[X25519_UNWRAP] stanza body", s->body, s->blen);
    memset(nonce,0,12);
    dl=cp_open(wk,nonce, NULL,0, s->body,(size_t)s->blen, fk);
    if(verbose) fprintf(stderr,"[X25519_UNWRAP] cp_open result: %d (%s)\n",dl,dl==0?"OK":"FAIL");
    if(dl==0) dbg_hex("[X25519_UNWRAP] file key", fk, 16);
    mem_wipe(shared,32); mem_wipe(wk,32);
    if(verbose) fprintf(stderr,"[X25519_UNWRAP] --- end ---\n");
    return dl;
}

/* ================================================================
 * AGE SCRYPT WRAP/UNWRAP
 * ================================================================ */

static int scrypt_wrap(const u8 *pw, size_t pl, int logN, stanza *s, const u8 *fk)
{
    u8 raw[16],fsalt[64],sk[32],nonce[12];
    static const char label[]="age-encryption.org/v1/scrypt";
    size_t ll=28;
    if(rand_bytes(raw,16)!=0) return -1;
    memcpy(fsalt,label,ll); memcpy(fsalt+ll,raw,16);
    if(verbose) fprintf(stderr,"[scrypt] N=2^%d, computing...\n",logN);
    if(scrypt_kdf(pw,pl, fsalt,ll+16, logN, sk,32)!=0) return -1;
    strcpy(s->type,"scrypt"); s->nargs=2;
    b64enc(raw,16,s->args[0]);
    sprintf(s->args[1],"%d",logN);
    memset(nonce,0,12);
    cp_seal(sk,nonce, NULL,0, fk,FILEKEY_SZ, s->body);
    s->blen=FILEKEY_SZ+16;
    mem_wipe(sk,32); return 0;
}

static int scrypt_unwrap(const u8 *pw, size_t pl, const stanza *s, u8 *fk)
{
    u8 raw[16],fsalt[64],sk[32],nonce[12];
    static const char label[]="age-encryption.org/v1/scrypt";
    size_t ll=28;
    int logN,dl;
    if(strcmp(s->type,"scrypt")!=0||s->nargs<2) return -1;
    dl=b64dec(s->args[0],strlen(s->args[0]),raw);
    if(dl!=16) return -1;
    logN=atoi(s->args[1]);
    if(logN<1||logN>30) return -1;
    memcpy(fsalt,label,ll); memcpy(fsalt+ll,raw,16);
    if(verbose) fprintf(stderr,"[scrypt] N=2^%d, computing...\n",logN);
    if(scrypt_kdf(pw,pl, fsalt,ll+16, logN, sk,32)!=0){
        mem_wipe(sk,32); return -2;
    }
    memset(nonce,0,12);
    dl=cp_open(sk,nonce, NULL,0, s->body,(size_t)s->blen, fk);
    if(dl!=0) fprintf(stderr,"error: wrong passphrase\n");
    mem_wipe(sk,32); return dl;
}

/* ================================================================
 * VERIFY HEADER MAC
 * ================================================================ */

static int verify_mac(const age_hdr *hdr, const u8 *fk)
{
    u8 hdrbuf[65536];
    int hlen;
    u8 hmac_key[32], computed[32];
    int diff,i;
    if(verbose) fprintf(stderr,"[MAC] --- verify_mac ---\n");
    dbg_hex("[MAC] file key", fk, 16);
    hkdf_sha256(fk,FILEKEY_SZ, NULL,0, (u8*)"header",6, hmac_key,32);
    dbg_hex("[MAC] hmac_key", hmac_key, 32);
    hlen=hdr_to_buf(hdr,hdrbuf,sizeof(hdrbuf));
    if(hlen<0){ if(verbose) fprintf(stderr,"[MAC] ERROR: hdr_to_buf failed\n"); return -1; }
    if(verbose) fprintf(stderr,"[MAC] canonical header (%d bytes):\n%.*s\n",hlen,hlen,(char*)hdrbuf);
    hmac_sha256(hmac_key,32, hdrbuf,(size_t)hlen, computed);
    mem_wipe(hmac_key,32);
    dbg_hex("[MAC] computed", computed, 32);
    dbg_hex("[MAC] stored", hdr->mac, 32);
    diff=0; for(i=0;i<32;i++) diff|=(computed[i]^hdr->mac[i]);
    if(verbose) fprintf(stderr,"[MAC] %s\n", diff?"FAIL: MACs differ":"OK: MACs match");
    mem_wipe(computed,32);
    return diff?-1:0;
}

/* ================================================================
 * PASSPHRASE
 * ================================================================ */

static int read_pass(const char *prompt, u8 *buf, size_t *len)
{
    char line[256];
    char *p;
    fprintf(stderr,"%s",prompt); fflush(stderr);
    p=fgets(line,sizeof(line),stdin);
    if(!p) return -1;
    *len=strlen(line);
    if(*len>0&&line[*len-1]=='\n'){line[*len-1]='\0';(*len)--;}
    if(*len>0&&line[*len-1]=='\r'){line[*len-1]='\0';(*len)--;}
    memcpy(buf,line,*len);
    mem_wipe(line,256);
    return 0;
}

/* ================================================================
 * MAIN
 * ================================================================ */

static void usage(const char *p)
{
    (void)p;
    fprintf(stderr,
"Usage:\n"
"  age89 [-v] -k                              Generate key pair\n"
"  age89 [-v] -e -r age1PUBKEY [-o OUT] [IN]  Encrypt with public key\n"
"  age89 [-v] -e -p           [-o OUT] [IN]   Encrypt with passphrase\n"
"  age89 [-v] -d -i AGE-SECRET-KEY-1... [-o OUT] [IN]  Decrypt with key\n"
"  age89 [-v] -d -p           [-o OUT] [IN]   Decrypt with passphrase\n"
"\n"
"  -v  Enable verbose diagnostic output (logs each derivation step)\n");
}

int main(int argc, char *argv[])
{
    int mode=0, use_pass=0, i;
    char *recip=NULL, *ident=NULL, *infile=NULL, *outfile=NULL;
    FILE *fin=stdin, *fout=stdout;

    srand((unsigned int)time(NULL));

    if(argc<2){usage(argv[0]);return 1;}
    for(i=1;i<argc;i++){
        if(!strcmp(argv[i],"-k"))       mode='k';
        else if(!strcmp(argv[i],"-e"))  mode='e';
        else if(!strcmp(argv[i],"-d"))  mode='d';
        else if(!strcmp(argv[i],"-p"))  use_pass=1;
        else if(!strcmp(argv[i],"-v"))  verbose=1;
        else if(!strcmp(argv[i],"-r")&&i+1<argc) recip=argv[++i];
        else if(!strcmp(argv[i],"-i")&&i+1<argc) ident=argv[++i];
        else if(!strcmp(argv[i],"-o")&&i+1<argc) outfile=argv[++i];
        else if(argv[i][0]!='-') infile=argv[i];
    }
    if(!mode){usage(argv[0]);return 1;}
    if(infile){fin=fopen(infile,"rb");if(!fin){perror(infile);return 1;}}
    if(outfile){fout=fopen(outfile,"wb");if(!fout){perror(outfile);return 1;}}

    /* GENERATE KEY PAIR */
    if(mode=='k'){
        u8 priv[32],pub[32];
        char priv_b[128],pub_b[128];
        int j;
        if(rand_bytes(priv,32)!=0) return 1;
        x25519_pubkey(pub,priv);
        bech32_encode("AGE-SECRET-KEY-",priv,32,priv_b);
        for(j=0;priv_b[j];j++) if(priv_b[j]>='a'&&priv_b[j]<='z') priv_b[j]-=32;
        bech32_encode("age",pub,32,pub_b);
        printf("# Public key (share this):\n%s\n\n# Private key (keep secret):\n%s\n",pub_b,priv_b);
        mem_wipe(priv,32);
        return 0;
    }

    /* ENCRYPT */
    if(mode=='e'){
        u8 fk[FILEKEY_SZ];
        age_hdr hdr;
        int ret;
        if(!use_pass&&!recip){fprintf(stderr,"error: specify -r PUBKEY or -p\n");return 1;}
        if(rand_bytes(fk,FILEKEY_SZ)!=0) return 1;
        memset(&hdr,0,sizeof(hdr)); hdr.ns=0;
        if(use_pass){
            u8 pw[256],pw2[256];
            size_t pl,pl2;            if(read_pass("Passphrase: ",pw,&pl)!=0) return 1;
            if(read_pass("Confirm: ",pw2,&pl2)!=0) return 1;
            if(pl!=pl2||memcmp(pw,pw2,pl)!=0){fprintf(stderr,"error: passphrases do not match\n");return 1;}
            ret=scrypt_wrap(pw,pl, 14, &hdr.s[0], fk);
            mem_wipe(pw,256); mem_wipe(pw2,256);
            if(ret!=0) return 1;
        } else {
            u8 pub[32];
            char hrp[64];
            size_t dl;
            char lower[256];
            int j;            for(j=0;recip[j];j++) lower[j]=(char)ascii_tolower((unsigned char)recip[j]);
            lower[j]='\0';
            if(bech32_decode(lower,hrp,pub,&dl)!=0||dl!=32){
                fprintf(stderr,"error: invalid public key\n");return 1;}
            if(strcmp(hrp,"age")!=0){fprintf(stderr,"error: invalid key prefix\n");return 1;}
            ret=x25519_wrap(pub,fk,&hdr.s[0]);
            if(ret!=0) return 1;
        }
        hdr.ns=1;
        ret=age_encrypt(fin,fout,fk,&hdr);
        mem_wipe(fk,FILEKEY_SZ);
        if(fin!=stdin) fclose(fin);
        if(fout!=stdout) fclose(fout);
        return ret?1:0;
    }

    /* DECRYPT */
    if(mode=='d'){
        age_hdr hdr;
        u8 fk[FILEKEY_SZ];
        int found=0,j,ret;
        if(!use_pass&&!ident){fprintf(stderr,"error: specify -i PRIVKEY or -p\n");return 1;}
        memset(&hdr,0,sizeof(hdr));
        if(verbose) fprintf(stderr,"[MAIN] Reading file header...\n");
        if(parse_hdr(fin,&hdr)!=0){fprintf(stderr,"error: reading header\n");return 1;}
        if(verbose){
            fprintf(stderr,"[MAIN] Header OK. Stanzas found: %d\n",hdr.ns);
            for(j=0;j<hdr.ns;j++)
                fprintf(stderr,"[MAIN]   stanza[%d]: type=\"%s\" nargs=%d blen=%d\n",
                        j,hdr.s[j].type,hdr.s[j].nargs,hdr.s[j].blen);
        }
        if(use_pass){
            u8 pw[256];
            int scrypt_ret;
            size_t pl;            if(read_pass("Passphrase: ",pw,&pl)!=0) return 1;
            if(verbose) fprintf(stderr,"[MAIN] Passphrase mode, length=%d\n",(int)pl);
            for(j=0;j<hdr.ns&&!found;j++)
                if(!strcmp(hdr.s[j].type,"scrypt")){
                    scrypt_ret=scrypt_unwrap(pw,pl,&hdr.s[j],fk);
                    if(scrypt_ret==0) found=1;
                    else if(scrypt_ret==-2){ mem_wipe(pw,256); return 1; }
                }
            mem_wipe(pw,256);
        } else {
            u8 priv[32],pub[32];
            char hrp[64];
            size_t dl;
            char lower[256];
            int k;
            if(verbose) fprintf(stderr,"[MAIN] Private key mode\n");
            dbg_str("[MAIN] ident (raw)", ident);
            for(k=0;ident[k];k++) lower[k]=(char)ascii_tolower((unsigned char)ident[k]);
            lower[k]='\0';
            dbg_str("[MAIN] ident (lowercase)", lower);
            if(verbose) fprintf(stderr,"[MAIN] ident length: %d chars\n",k);
            if(bech32_decode(lower,hrp,priv,&dl)!=0||dl!=32){
                fprintf(stderr,"error: invalid private key (dl=%d hrp=%s)\n",(int)dl,hrp);
                return 1;}
            dbg_str("[MAIN] decoded HRP", hrp);
            dbg_hex("[MAIN] private key (bytes)", priv, 32);
            x25519_pubkey(pub,priv);
            dbg_hex("[MAIN] derived public key", pub, 32);
            for(j=0;j<hdr.ns&&!found;j++){
                if(verbose) fprintf(stderr,"[MAIN] trying stanza[%d] type=\"%s\"...\n",j,hdr.s[j].type);
                if(!strcmp(hdr.s[j].type,"X25519"))
                    if(x25519_unwrap(priv,pub,&hdr.s[j],fk)==0) found=1;
            }
            mem_wipe(priv,32);
        }
        if(!found){fprintf(stderr,"error: no identity matched any recipient\n");return 1;}
        if(verify_mac(&hdr,fk)!=0){
            fprintf(stderr,"error: invalid header MAC (file corrupted)\n");
            mem_wipe(fk,FILEKEY_SZ);return 1;
        }
        ret=age_decrypt(fin,fout,fk);
        mem_wipe(fk,FILEKEY_SZ);
        if(fin!=stdin) fclose(fin);
        if(fout!=stdout) fclose(fout);
        return ret?1:0;
    }

    usage(argv[0]);
    return 1;
}
