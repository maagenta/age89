/*
 * age89.c - age v1 compatible encryptor/decryptor
 *
 * Compatible with Debian 3 (woody) and gcc 2.95.4 (C89/C90)
 * Build: gcc -O2 -o age89 age89.c
 *
 * Algorithms: X25519, ChaCha20-Poly1305, HKDF-SHA256, scrypt, Bech32
 *
 * Usage:
 *   Generate key pair:     age89 -k
 *   Encrypt (public key):  age89 -e -r age1PUBKEY [-o OUTPUT] [INPUT]
 *   Encrypt (passphrase):  age89 -e -p [-o OUTPUT] [INPUT]
 *   Decrypt (private key): age89 -d -i AGE-SECRET-KEY-1... [-o OUTPUT] [INPUT]
 *   Decrypt (passphrase):  age89 -d -p [-o OUTPUT] [INPUT]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef long long           s64;

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
    b[0]=(u8)x;      b[1]=(u8)(x>>8);  b[2]=(u8)(x>>16); b[3]=(u8)(x>>24);
    b[4]=(u8)(x>>32); b[5]=(u8)(x>>40); b[6]=(u8)(x>>48); b[7]=(u8)(x>>56);
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
static void sha256_init(sha256_ctx *ctx){
    ctx->s[0]=0x6a09e667UL;ctx->s[1]=0xbb67ae85UL;
    ctx->s[2]=0x3c6ef372UL;ctx->s[3]=0xa54ff53aUL;
    ctx->s[4]=0x510e527fUL;ctx->s[5]=0x9b05688cUL;
    ctx->s[6]=0x1f83d9abUL;ctx->s[7]=0x5be0cd19UL;
    ctx->n=0;ctx->bl=0;
}
static void sha256_update(sha256_ctx *ctx, const u8 *d, size_t len){
    size_t i;
    for(i=0;i<len;i++){
        ctx->b[ctx->bl++]=d[i]; ctx->n++;
        if(ctx->bl==64){sha256_transform(ctx,ctx->b);ctx->bl=0;}
    }
}
static void sha256_final(sha256_ctx *ctx, u8 *out){
    u8 pad[64];
    u64 bits;
    int pl,i;
    bits=ctx->n*8;
    memset(pad,0,64); pad[0]=0x80;
    pl=(ctx->bl<56)?(56-ctx->bl):(120-ctx->bl);
    sha256_update(ctx,pad,(size_t)pl);
    pad[0]=(u8)(bits>>56);pad[1]=(u8)(bits>>48);pad[2]=(u8)(bits>>40);pad[3]=(u8)(bits>>32);
    pad[4]=(u8)(bits>>24);pad[5]=(u8)(bits>>16);pad[6]=(u8)(bits>>8);pad[7]=(u8)bits;
    sha256_update(ctx,pad,8);
    for(i=0;i<8;i++) store32_be(out+i*4,ctx->s[i]);
}
static void sha256_hash(const u8 *d, size_t n, u8 *out){
    sha256_ctx c; sha256_init(&c); sha256_update(&c,d,n); sha256_final(&c,out);
    mem_wipe(&c,sizeof(c));
}

/* ================================================================
 * HMAC-SHA256
 * ================================================================ */

typedef struct { sha256_ctx in, out; } hmac_ctx;

static void hmac_init(hmac_ctx *ctx, const u8 *key, size_t klen){
    u8 k[64],ip[64],op[64]; int i;
    memset(k,0,64);
    if(klen>64) sha256_hash(key,klen,k); else memcpy(k,key,klen);
    for(i=0;i<64;i++){ip[i]=k[i]^0x36;op[i]=k[i]^0x5c;}
    sha256_init(&ctx->in);  sha256_update(&ctx->in,ip,64);
    sha256_init(&ctx->out); sha256_update(&ctx->out,op,64);
    mem_wipe(k,64);
}
static void hmac_update(hmac_ctx *ctx, const u8 *d, size_t n){sha256_update(&ctx->in,d,n);}
static void hmac_final(hmac_ctx *ctx, u8 *mac){
    u8 t[32]; sha256_final(&ctx->in,t);
    sha256_update(&ctx->out,t,32); sha256_final(&ctx->out,mac);
    mem_wipe(t,32);
}
static void hmac_sha256(const u8 *k, size_t kl, const u8 *d, size_t dl, u8 *mac){
    hmac_ctx c; hmac_init(&c,k,kl); hmac_update(&c,d,dl); hmac_final(&c,mac);
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
    if(salt&&sl) hmac_sha256(salt,sl,ikm,il,prk);
    else         hmac_sha256(z32,32,ikm,il,prk);
    done=0; ctr=0;
    while(done<ol){
        size_t chunk;
        ctr++;
        hmac_init(&c,prk,32);
        if(done>0) hmac_update(&c,t,32);
        if(info&&nl) hmac_update(&c,info,nl);
        hmac_update(&c,&ctr,1);
        hmac_final(&c,t);
        chunk=ol-done; if(chunk>32)chunk=32;
        memcpy(out+done,t,chunk); done+=chunk;
    }
    mem_wipe(prk,32); mem_wipe(t,32); mem_wipe(&c,sizeof(c));
}

/* ================================================================
 * PBKDF2-HMAC-SHA256
 * ================================================================ */

static void pbkdf2_sha256(const u8 *pw, size_t pl, const u8 *salt, size_t sl,
                           u32 iters, u8 *out, size_t ol)
{
    u32 blk; size_t done;
    done=0; blk=0;
    while(done<ol){
        u8 u[32],t[32],tmp[4]; u32 i; int j; hmac_ctx c;
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
    u32 x[16],B[16]; int i;
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
    u8 X[64]; int i;
    int nb=2*r;
    memcpy(X,B+(nb-1)*64,64);
    for(i=0;i<nb;i++){
        int j; for(j=0;j<64;j++) X[j]^=B[i*64+j];
        salsa20_8(X); memcpy(Y+i*64,X,64);
    }
    for(i=0;i<r;i++) memcpy(B+i*64,    Y+2*i*64,    64);
    for(i=0;i<r;i++) memcpy(B+(r+i)*64,Y+(2*i+1)*64,64);
}

static int scrypt_romix(u8 *B, u64 N, int r)
{
    size_t bsz=(size_t)(128*r);
    u8 *V,*Y,*X;
    u64 i,j;
    V=(u8*)malloc((size_t)(N*bsz));
    Y=(u8*)malloc(bsz);
    X=(u8*)malloc(bsz);
    if(!V||!Y||!X){free(V);free(Y);free(X);return -1;}
    memcpy(X,B,bsz);
    for(i=0;i<N;i++){memcpy(V+i*bsz,X,bsz);blockmix(X,Y,r);}
    for(i=0;i<N;i++){
        u8 *last=X+(2*r-1)*64;
        j=(u64)load32_le(last)|((u64)load32_le(last+4)<<32);
        j&=(N-1);
        {size_t k; for(k=0;k<bsz;k++) X[k]^=V[j*bsz+k];}
        blockmix(X,Y,r);
    }
    memcpy(B,X,bsz);
    mem_wipe(X,bsz);mem_wipe(Y,bsz);mem_wipe(V,(size_t)(N*bsz));
    free(X);free(Y);free(V);
    return 0;
}

static int scrypt_kdf(const u8 *pw, size_t pl, const u8 *salt, size_t sl,
                       int logN, u8 *out, size_t ol)
{
    u64 N; u8 B[1024];
    if(logN<1||logN>30) return -1;
    N=(u64)1<<logN;
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
static void cha_block(u32 *out, const u32 *in){
    u32 x[16]; int i;
    memcpy(x,in,64);
    for(i=0;i<10;i++){
        QR(x[0],x[4],x[8],x[12]);QR(x[1],x[5],x[9],x[13]);
        QR(x[2],x[6],x[10],x[14]);QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]);QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8],x[13]);QR(x[3],x[4],x[9],x[14]);
    }
    for(i=0;i<16;i++) out[i]=x[i]+in[i];
}
static void cha_init(cha_ctx *ctx, const u8 *key, const u8 *nonce, u32 ctr){
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
static void cha_xor(cha_ctx *ctx, const u8 *in, u8 *out, size_t n){
    size_t i;
    for(i=0;i<n;i++){
        if(ctx->pos==64){
            u32 bl[16]; int j;
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

static void p1305_init(p1305_ctx *ctx, const u8 *key){
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
static void p1305_block(p1305_ctx *ctx, const u8 *m, int hi){
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
    d0=(u64)h0*r0+(u64)h1*s4+(u64)h2*s3+(u64)h3*s2+(u64)h4*s1;
    d1=(u64)h0*r1+(u64)h1*r0+(u64)h2*s4+(u64)h3*s3+(u64)h4*s2;
    d2=(u64)h0*r2+(u64)h1*r1+(u64)h2*r0+(u64)h3*s4+(u64)h4*s3;
    d3=(u64)h0*r3+(u64)h1*r2+(u64)h2*r1+(u64)h3*r0+(u64)h4*s4;
    d4=(u64)h0*r4+(u64)h1*r3+(u64)h2*r2+(u64)h3*r1+(u64)h4*r0;
    c=(u32)(d0>>26);h0=(u32)d0&0x3ffffff;d1+=c;
    c=(u32)(d1>>26);h1=(u32)d1&0x3ffffff;d2+=c;
    c=(u32)(d2>>26);h2=(u32)d2&0x3ffffff;d3+=c;
    c=(u32)(d3>>26);h3=(u32)d3&0x3ffffff;d4+=c;
    c=(u32)(d4>>26);h4=(u32)d4&0x3ffffff;h0+=c*5;
    c=h0>>26;h0&=0x3ffffff;h1+=c;
    ctx->h[0]=h0;ctx->h[1]=h1;ctx->h[2]=h2;ctx->h[3]=h3;ctx->h[4]=h4;
}
static void p1305_update(p1305_ctx *ctx, const u8 *m, size_t n){
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
static void p1305_final(p1305_ctx *ctx, u8 *mac){
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
    /* reassemble 26-bit limbs into 32-bit words, then add pad with carry */
    h0=((h0    )|(h1<<26))&0xffffffffu;
    h1=((h1>> 6)|(h2<<20))&0xffffffffu;
    h2=((h2>>12)|(h3<<14))&0xffffffffu;
    h3=((h3>>18)|(h4<< 8))&0xffffffffu;
    f=(u64)h0+ctx->pad[0]; store32_le(mac+ 0,(u32)f);
    f=(u64)h1+ctx->pad[1]+(f>>32); store32_le(mac+ 4,(u32)f);
    f=(u64)h2+ctx->pad[2]+(f>>32); store32_le(mac+ 8,(u32)f);
    f=(u64)h3+ctx->pad[3]+(f>>32); store32_le(mac+12,(u32)f);
    mem_wipe(ctx,sizeof(*ctx));
}

/* ================================================================
 * CHACHA20-POLY1305 AEAD (RFC 8439)
 * ================================================================ */

static void cp_mac_segment(p1305_ctx *mac, const u8 *d, size_t n){
    static const u8 z[16]={0};
    p1305_update(mac,d,n);
    if(n%16) p1305_update(mac,z,16-(n%16));
}

static void cp_seal(const u8 *key, const u8 *nonce,
                    const u8 *aad, size_t al,
                    const u8 *plain, size_t pl, u8 *out)
{
    cha_ctx s; p1305_ctx mac; u8 otk[64],zeros[64],lens[16];
    memset(zeros,0,64);
    cha_init(&s,key,nonce,0); cha_xor(&s,zeros,otk,64);
    cha_init(&s,key,nonce,1); cha_xor(&s,plain,out,pl);
    p1305_init(&mac,otk);
    cp_mac_segment(&mac,aad,al);
    cp_mac_segment(&mac,out,pl);
    store64_le(lens+0,(u64)al); store64_le(lens+8,(u64)pl);
    p1305_update(&mac,lens,16); p1305_final(&mac,out+pl);
    mem_wipe(&s,sizeof(s)); mem_wipe(otk,64);
}

static int cp_open(const u8 *key, const u8 *nonce,
                   const u8 *aad, size_t al,
                   const u8 *cipher, size_t cl, u8 *out)
{
    cha_ctx s; p1305_ctx mac; u8 otk[64],zeros[64],lens[16],tag[16];
    size_t pl; int diff,i;
    if(cl<16) return -1; pl=cl-16;
    memset(zeros,0,64);
    cha_init(&s,key,nonce,0); cha_xor(&s,zeros,otk,64);
    p1305_init(&mac,otk);
    cp_mac_segment(&mac,aad,al);
    cp_mac_segment(&mac,cipher,pl);
    store64_le(lens+0,(u64)al); store64_le(lens+8,(u64)pl);
    p1305_update(&mac,lens,16); p1305_final(&mac,tag);
    diff=0; for(i=0;i<16;i++) diff|=(tag[i]^cipher[pl+i]);
    mem_wipe(otk,64); mem_wipe(tag,16);
    if(diff) return -1;
    cha_init(&s,key,nonce,1); cha_xor(&s,cipher,out,pl);
    mem_wipe(&s,sizeof(s)); return 0;
}

/* ================================================================
 * CURVE25519 / X25519
 * Based on TweetNaCl (public domain)
 * GF(2^255-19) with 16 limbs of 16-bit signed values
 * ================================================================ */

typedef s64 gf[16];

static void gf0(gf r){int i;for(i=0;i<16;i++)r[i]=0;}
static void gf1(gf r){gf0(r);r[0]=1;}
static void gfcp(gf r,const gf a){int i;for(i=0;i<16;i++)r[i]=a[i];}
static void gfadd(gf r,const gf a,const gf b){int i;for(i=0;i<16;i++)r[i]=a[i]+b[i];}
static void gfsub(gf r,const gf a,const gf b){int i;for(i=0;i<16;i++)r[i]=a[i]-b[i];}

static void gfcar(gf r){
    int i; s64 c;
    for(i=0;i<16;i++){
        r[i]+=(1LL<<16); c=r[i]>>16;
        r[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
        r[i]-=c<<16;
    }
}
static void gfsel(gf p, gf q, int b){
    s64 t,c=~(b-1); int i;
    for(i=0;i<16;i++){t=c&(p[i]^q[i]);p[i]^=t;q[i]^=t;}
}
static void gfmul(gf r,const gf a,const gf b){
    s64 t[31]; int i,j;
    for(i=0;i<31;i++) t[i]=0;
    for(i=0;i<16;i++) for(j=0;j<16;j++) t[i+j]+=a[i]*b[j];
    /* Reduce: 2^(256+16i) = 38 * 2^(16i), so t[i] += 38*t[i+16] */
    for(i=0;i<15;i++) t[i]+=38*t[i+16];
    /* Propagate carry through t[0..14] */
    for(i=0;i<15;i++){t[i+1]+=t[i]>>16;t[i]&=0xffff;}
    /* t[16] was reduced above; now handle overflow from t[15] only */
    t[0]+=38*(t[15]>>16); t[15]&=0xffff;
    /* Final carry propagation */
    for(i=0;i<15;i++){t[i+1]+=t[i]>>16;t[i]&=0xffff;}
    for(i=0;i<16;i++) r[i]=t[i];
}
static void gfsqr(gf r,const gf a){gfmul(r,a,a);}

static void gfpack(u8 *o,const gf n){
    gf m,t; int i,j,b;
    gfcp(t,n); gfcar(t); gfcar(t); gfcar(t);
    for(j=0;j<2;j++){
        m[0]=t[0]-0xffed;
        for(i=1;i<15;i++){m[i]=t[i]-0xffff-((m[i-1]>>16)&1);m[i-1]&=0xffff;}
        m[15]=t[15]-0x7fff-((m[14]>>16)&1);
        b=(int)((m[15]>>16)&1); m[14]&=0xffff;
        gfsel(t,m,1-b);
    }
    for(i=0;i<16;i++){o[2*i]=(u8)(t[i]&0xff);o[2*i+1]=(u8)(t[i]>>8);}
}
static void gfunpack(gf r,const u8 *n){
    int i;
    for(i=0;i<16;i++) r[i]=(s64)n[2*i]+((s64)n[2*i+1]<<8);
    r[15]&=0x7fff;
}
static void gfinv(gf r,const gf a){
    gf t,c; int i;
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
    /* a24 = 121665 = 0x1DB41 */
    static const gf a24={0xDB41,1};
    int swap,i,bit;

    memcpy(e,scalar,32);
    e[0]&=248; e[31]&=127; e[31]|=64;

    gfunpack(x1,point); /* x1 = u (input point x-coord) */
    gf1(x2);             /* x2 = 1 */
    gf0(z2);             /* z2 = 0 */
    gfcp(x3,x1);         /* x3 = u */
    gf1(z3);             /* z3 = 1 */

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
        gfmul(z3,z3,x1);       /* z3 = x1 * (DA-CB)^2 */
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

static int rand_bytes(u8 *buf, size_t n){
    FILE *f=fopen("/dev/urandom","rb");
    size_t r;
    if(!f){fprintf(stderr,"error: cannot open /dev/urandom\n");return -1;}
    r=fread(buf,1,n,f); fclose(f);
    return (r==n)?0:-1;
}

/* ================================================================
 * BASE64 without padding (RawStdEncoding)
 * ================================================================ */

static const char B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64enc(const u8 *src, size_t sl, char *dst){
    size_t i; char *p=dst;
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

static int b64dec(const char *src, size_t sl, u8 *dst){
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
    size_t i; int out=0,bits=0; u32 acc=0;
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

static u32 bech32_pm(const u8 *v, size_t n){
    static const u32 G[5]={0x3b6a57b2UL,0x26508e6dUL,0x1ea119faUL,0x3d4233ddUL,0x2a1462b3UL};
    u32 c=1; size_t i; int j;
    for(i=0;i<n;i++){
        u8 top=(u8)(c>>25);
        c=((c&0x1ffffff)<<5)^v[i];
        for(j=0;j<5;j++) if((top>>j)&1) c^=G[j];
    }
    return c;
}

static int bech32_encode(const char *hrp, const u8 *data, size_t dl, char *out){
    size_t hl=strlen(hrp), i;
    u8 exp[256]; size_t el=0;
    u8 d5[256];  size_t d5l=0;
    u8 all[512]; size_t al;
    u32 chk; char *p=out;
    u32 acc=0; int bits=0;

    /* HRP expand (always lowercase per BIP-173 spec) */
    for(i=0;i<hl;i++) exp[el++]=(u8)(ascii_tolower((unsigned char)hrp[i])>>5);
    exp[el++]=0;
    for(i=0;i<hl;i++) exp[el++]=(u8)(ascii_tolower((unsigned char)hrp[i])&31);

    /* bytes -> 5-bit groups */
    for(i=0;i<dl;i++){
        acc=(acc<<8)|data[i]; bits+=8;
        while(bits>=5){bits-=5;d5[d5l++]=(u8)((acc>>bits)&31);}
    }
    if(bits) d5[d5l++]=(u8)((acc<<(5-bits))&31);

    /* build all = exp + d5 + 6 zeros for checksum computation */
    al=0;
    memcpy(all+al,exp,el); al+=el;
    memcpy(all+al,d5,d5l); al+=d5l;
    memset(all+al,0,6); al+=6;
    chk=bech32_pm(all,al)^1;

    /* write output */
    memcpy(p,hrp,hl); p+=hl; *p++='1';
    for(i=0;i<d5l;i++) *p++=BC[d5[i]];
    for(i=0;i<6;i++) *p++=BC[(chk>>(5*(5-(int)i)))&31];
    *p='\0'; return 0;
}

static int bech32_decode(const char *str, char *hrp, u8 *data, size_t *dl){
    size_t sl=strlen(str), i;
    int pos=-1;
    u8 exp[256]; size_t el=0;
    u8 d5[256];  size_t d5l=0;
    u8 all[512]; size_t al;
    u32 chk;
    u32 acc=0; int bits=0;

    for(i=0;i<sl;i++) if(str[i]=='1') pos=(int)i;
    if(pos<1||(size_t)pos+7>sl) return -1;

    memcpy(hrp,str,(size_t)pos); hrp[pos]='\0';
    {
        size_t hl=(size_t)pos;
        for(i=0;i<hl;i++) exp[el++]=(u8)(hrp[i]>>5);
        exp[el++]=0;
        for(i=0;i<hl;i++) exp[el++]=(u8)(hrp[i]&31);
    }

    for(i=(size_t)pos+1;i<sl;i++){
        int ci; u8 v=255;
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

    d5l-=6; /* strip checksum */
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
#define BYTES_PL     48  /* 64/4*3 */

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

/* Write header (without MAC suffix) to buffer. Returns bytes written. */
static int hdr_to_buf(const age_hdr *hdr, u8 *buf, size_t bufsize)
{
    int n=0,i,j;
    char tmp[512];
    int r;
    /* intro */
    r=sprintf(tmp,"age-encryption.org/v1\n");
    if((size_t)(n+r)>bufsize) return -1;
    memcpy(buf+n,tmp,(size_t)r); n+=r;
    /* stanzas */
    for(i=0;i<hdr->ns;i++){
        const stanza *s=&hdr->s[i];
        char enc[MAX_BODY*2];
        size_t enclen;
        size_t pos;
        r=sprintf(tmp,"-> %s",s->type);
        if((size_t)(n+r)>bufsize) return -1;
        memcpy(buf+n,tmp,(size_t)r); n+=r;
        for(j=0;j<s->nargs;j++){
            r=sprintf(tmp," %s",s->args[j]);
            if((size_t)(n+r)>bufsize) return -1;
            memcpy(buf+n,tmp,(size_t)r); n+=r;
        }
        buf[n++]='\n';
        /* body: base64, wrapped at 64 cols, must end with a short line */
        b64enc(s->body,(size_t)s->blen,enc);
        enclen=strlen(enc);
        pos=0;
        while(pos<enclen){
            size_t chunk=(enclen-pos>(size_t)COLS)?(size_t)COLS:(enclen-pos);
            if((size_t)(n+(int)chunk+1)>bufsize) return -1;
            memcpy(buf+n,enc+pos,chunk); n+=(int)chunk;
            buf[n++]='\n'; pos+=chunk;
        }
        /* always end with a short line */
        if(enclen==0||enclen%COLS==0){
            if((size_t)(n+1)>bufsize) return -1;
            buf[n++]='\n';
        }
    }
    /* footer prefix (without MAC) */
    r=sprintf(tmp,"---");
    if((size_t)(n+r)>bufsize) return -1;
    memcpy(buf+n,tmp,(size_t)r); n+=r;
    return n;
}

static void write_hdr(FILE *fp, const age_hdr *hdr)
{
    u8 buf[65536]; int n; char mac_b64[64];
    n=hdr_to_buf(hdr,buf,sizeof(buf));
    if(n<0){fprintf(stderr,"error: header too large\n");return;}
    fwrite(buf,1,(size_t)n,fp);
    b64enc(hdr->mac,32,mac_b64);
    fprintf(fp," %s\n",mac_b64);
}

static int read_line(FILE *fp, char *buf, int max){
    int c,n=0;
    while((c=fgetc(fp))!=EOF){
        if(c=='\n'){buf[n]='\0';return n;}
        if(n<max-1) buf[n++]=(char)c;
    }
    if(n>0){buf[n]='\0';return n;}
    return -1;
}

static int parse_hdr(FILE *fp, age_hdr *hdr){
    char line[512];
    hdr->ns=0;
    if(read_line(fp,line,sizeof(line))<0) return -1;
    if(strcmp(line,"age-encryption.org/v1")!=0){
        fprintf(stderr,"error: invalid age format\n"); return -1;
    }
    for(;;){
        if(read_line(fp,line,sizeof(line))<0) return -1;
        if(strncmp(line,"---",3)==0){
            /* footer: "--- <mac_b64>" */
            u8 tmp[64]; int dl;
            char *mac_b64=line+4;
            dl=b64dec(mac_b64,strlen(mac_b64),tmp);
            if(dl!=32){fprintf(stderr,"error: invalid MAC\n");return -1;}
            memcpy(hdr->mac,tmp,32); break;
        }
        if(strncmp(line,"-> ",3)==0){
            stanza *s; char linecopy[512]; char *tok;
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
            /* read body lines until a short line */
            for(;;){
                u8 dec[BYTES_PL+4]; int dl; int rl;
                char bline[128];
                rl=read_line(fp,bline,sizeof(bline));
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
    u8 hdrbuf[65536]; int hlen;
    u8 hmac_key[32];
    u8 snonce[16], skey[32];
    u8 cnonce[12], plain[65536], cipher[65536+16];
    u64 idx;
    int last;

    /* Compute header MAC */
    hkdf_sha256(fk,FILEKEY_SZ, NULL,0, (u8*)"header",6, hmac_key,32);
    hlen=hdr_to_buf(hdr,hdrbuf,sizeof(hdrbuf));
    if(hlen<0) return -1;
    hmac_sha256(hmac_key,32, hdrbuf,(size_t)hlen, hdr->mac);
    mem_wipe(hmac_key,32);

    write_hdr(fout,hdr);

    /* Stream nonce and key */
    if(rand_bytes(snonce,16)!=0) return -1;
    fwrite(snonce,1,16,fout);
    hkdf_sha256(fk,FILEKEY_SZ, snonce,16, (u8*)"payload",7, skey,32);

    /* Encrypt chunks */
    memset(cnonce,0,12); idx=0; last=0;
    while(!last){
        size_t nr=fread(plain,1,65536,fin);
        int peek;
        if(nr<65536) last=1;
        else{peek=fgetc(fin);if(peek==EOF)last=1;else ungetc(peek,fin);}
        /* chunk nonce: [0,0,0, idx_be8, flag] */
        cnonce[0]=0;cnonce[1]=0;cnonce[2]=0;
        cnonce[3]=(u8)(idx>>56);cnonce[4]=(u8)(idx>>48);cnonce[5]=(u8)(idx>>40);
        cnonce[6]=(u8)(idx>>32);cnonce[7]=(u8)(idx>>24);cnonce[8]=(u8)(idx>>16);
        cnonce[9]=(u8)(idx>>8);cnonce[10]=(u8)idx;
        cnonce[11]=last?0x01:0x00;
        cp_seal(skey,cnonce, NULL,0, plain,nr, cipher);
        fwrite(cipher,1,nr+16,fout);
        idx++;
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
    idx=0;
    for(;;){
        size_t nr=fread(cipher,1,65536+16,fin);
        int last=0,ret;
        if(nr<16&&nr>0){fprintf(stderr,"error: invalid chunk\n");mem_wipe(skey,32);return -1;}
        if(nr==0) break;
        cnonce[0]=0;cnonce[1]=0;cnonce[2]=0;
        cnonce[3]=(u8)(idx>>56);cnonce[4]=(u8)(idx>>48);cnonce[5]=(u8)(idx>>40);
        cnonce[6]=(u8)(idx>>32);cnonce[7]=(u8)(idx>>24);cnonce[8]=(u8)(idx>>16);
        cnonce[9]=(u8)(idx>>8);cnonce[10]=(u8)idx;
        cnonce[11]=0x00;
        ret=cp_open(skey,cnonce, NULL,0, cipher,nr, plain);
        if(ret!=0){
            cnonce[11]=0x01;
            ret=cp_open(skey,cnonce, NULL,0, cipher,nr, plain);
            if(ret!=0){
                fprintf(stderr,"error: authentication failed on chunk %llu\n",(unsigned long long)idx);
                mem_wipe(skey,32); return -1;
            }
            last=1;
        } else if(nr<(size_t)(65536+16)){
            last=1;
        }
        fwrite(plain,1,nr-16,fout);
        idx++; if(last) break;
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
    if(strcmp(s->type,"X25519")!=0||s->nargs<1) return -1;
    dl=b64dec(s->args[0],strlen(s->args[0]),epub);
    if(dl!=32) return -1;
    x25519(shared,priv,epub);
    memcpy(salt,epub,32); memcpy(salt+32,pub,32);
    hkdf_sha256(shared,32, salt,64, (u8*)"age-encryption.org/v1/X25519",28, wk,32);
    memset(nonce,0,12);
    dl=cp_open(wk,nonce, NULL,0, s->body,(size_t)s->blen, fk);
    mem_wipe(shared,32); mem_wipe(wk,32);
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
    fprintf(stderr,"[scrypt] N=2^%d, computing...\n",logN);
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
    size_t ll=28; int logN,dl;
    if(strcmp(s->type,"scrypt")!=0||s->nargs<2) return -1;
    dl=b64dec(s->args[0],strlen(s->args[0]),raw);
    if(dl!=16) return -1;
    logN=atoi(s->args[1]);
    if(logN<1||logN>30) return -1;
    memcpy(fsalt,label,ll); memcpy(fsalt+ll,raw,16);
    fprintf(stderr,"[scrypt] N=2^%d, computing...\n",logN);
    if(scrypt_kdf(pw,pl, fsalt,ll+16, logN, sk,32)!=0) return -1;
    memset(nonce,0,12);
    dl=cp_open(sk,nonce, NULL,0, s->body,(size_t)s->blen, fk);
    mem_wipe(sk,32); return dl;
}

/* ================================================================
 * VERIFY HEADER MAC
 * ================================================================ */

static int verify_mac(const age_hdr *hdr, const u8 *fk)
{
    u8 hdrbuf[65536]; int hlen;
    u8 hmac_key[32], computed[32];
    int diff,i;
    hkdf_sha256(fk,FILEKEY_SZ, NULL,0, (u8*)"header",6, hmac_key,32);
    hlen=hdr_to_buf(hdr,hdrbuf,sizeof(hdrbuf));
    if(hlen<0) return -1;
    hmac_sha256(hmac_key,32, hdrbuf,(size_t)hlen, computed);
    mem_wipe(hmac_key,32);
    diff=0; for(i=0;i<32;i++) diff|=(computed[i]^hdr->mac[i]);
    mem_wipe(computed,32);
    return diff?-1:0;
}

/* ================================================================
 * PASSPHRASE
 * ================================================================ */

static int read_pass(const char *prompt, u8 *buf, size_t *len)
{
    char line[256]; char *p;
    fprintf(stderr,"%s",prompt); fflush(stderr);
    system("stty -echo 2>/dev/null");
    p=fgets(line,sizeof(line),stdin);
    system("stty echo 2>/dev/null");
    fprintf(stderr,"\n");
    if(!p) return -1;
    *len=strlen(line);
    if(*len>0&&line[*len-1]=='\n'){line[*len-1]='\0';(*len)--;}
    memcpy(buf,line,*len);
    mem_wipe(line,256);
    return 0;
}

/* ================================================================
 * MAIN
 * ================================================================ */

static void usage(const char *p){
    fprintf(stderr,
"Usage:\n"
"  %s -k                              Generate key pair\n"
"  %s -e -r age1PUBKEY [-o OUT] [IN]  Encrypt with public key\n"
"  %s -e -p           [-o OUT] [IN]  Encrypt with passphrase\n"
"  %s -d -i AGE-SECRET-KEY-1... [-o OUT] [IN]  Decrypt with key\n"
"  %s -d -p           [-o OUT] [IN]  Decrypt with passphrase\n",
p,p,p,p,p);
}

int main(int argc, char *argv[])
{
    int mode=0, use_pass=0, i;
    char *recip=NULL, *ident=NULL, *infile=NULL, *outfile=NULL;
    FILE *fin=stdin, *fout=stdout;

    if(argc<2){usage(argv[0]);return 1;}
    for(i=1;i<argc;i++){
        if(!strcmp(argv[i],"-k"))       mode='k';
        else if(!strcmp(argv[i],"-e"))  mode='e';
        else if(!strcmp(argv[i],"-d"))  mode='d';
        else if(!strcmp(argv[i],"-p"))  use_pass=1;
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
        for(j=0;priv_b[j];j++) priv_b[j]=(char)ascii_tolower(priv_b[j])^('a'^'A')*(priv_b[j]>='a'&&priv_b[j]<='z');
        /* uppercase the private key string */
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
            u8 pw[256],pw2[256]; size_t pl,pl2;
            if(read_pass("Passphrase: ",pw,&pl)!=0) return 1;
            if(read_pass("Confirm: ",pw2,&pl2)!=0) return 1;
            if(pl!=pl2||memcmp(pw,pw2,pl)!=0){fprintf(stderr,"error: passphrases do not match\n");return 1;}
            ret=scrypt_wrap(pw,pl, 14, &hdr.s[0], fk);
            mem_wipe(pw,256); mem_wipe(pw2,256);
            if(ret!=0) return 1;
        } else {
            u8 pub[32]; char hrp[64]; size_t dl;
            char lower[256]; int j;
            for(j=0;recip[j];j++) lower[j]=(char)ascii_tolower((unsigned char)recip[j]);
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
        age_hdr hdr; u8 fk[FILEKEY_SZ]; int found=0,j,ret;
        if(!use_pass&&!ident){fprintf(stderr,"error: specify -i PRIVKEY or -p\n");return 1;}
        memset(&hdr,0,sizeof(hdr));
        if(parse_hdr(fin,&hdr)!=0){fprintf(stderr,"error: reading header\n");return 1;}
        if(use_pass){
            u8 pw[256]; size_t pl;
            if(read_pass("Passphrase: ",pw,&pl)!=0) return 1;
            for(j=0;j<hdr.ns&&!found;j++)
                if(!strcmp(hdr.s[j].type,"scrypt"))
                    if(scrypt_unwrap(pw,pl,&hdr.s[j],fk)==0) found=1;
            mem_wipe(pw,256);
        } else {
            u8 priv[32],pub[32]; char hrp[64]; size_t dl;
            char lower[256]; int k;
            for(k=0;ident[k];k++) lower[k]=(char)ascii_tolower((unsigned char)ident[k]);
            lower[k]='\0';
            if(bech32_decode(lower,hrp,priv,&dl)!=0||dl!=32){
                fprintf(stderr,"error: invalid private key\n");return 1;}
            x25519_pubkey(pub,priv);
            for(j=0;j<hdr.ns&&!found;j++)
                if(!strcmp(hdr.s[j].type,"X25519"))
                    if(x25519_unwrap(priv,pub,&hdr.s[j],fk)==0) found=1;
            mem_wipe(priv,32);
        }
        if(!found){fprintf(stderr,"error: no identity matched any recipient\n");return 1;}
        if(verify_mac(&hdr,fk)!=0){
            fprintf(stderr,"error: invalid header MAC (file corrupted)\n");mem_wipe(fk,FILEKEY_SZ);return 1;}
        ret=age_decrypt(fin,fout,fk);
        mem_wipe(fk,FILEKEY_SZ);
        if(fin!=stdin) fclose(fin);
        if(fout!=stdout) fclose(fout);
        return ret?1:0;
    }

    usage(argv[0]);
    return 1;
}
