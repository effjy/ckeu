gcc -O2 -Wall -Wextra -Werror -std=c99 -DKYBER_K=4 -I. -Ikyber \
    ckeu.c \
    kyber/cbd.c kyber/fips202.c kyber/indcpa.c kyber/kem.c \
    kyber/ntt.c kyber/poly.c kyber/polyvec.c kyber/reduce.c \
    kyber/symmetric-shake.c kyber/verify.c kyber/randombytes.c \
    -DOPENSSLDIR="\"/dev/null\"" \
    -DENGINESDIR="\"/dev/null\"" \
    -DMODULESDIR="\"/dev/null\"" \
    -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -fno-builtin-memset -fno-strict-aliasing \
    -Wl,-z,relro,-z,now \
    -Wl,-Bstatic -lcrypto -largon2 -Wl,-Bdynamic \
    -latomic -lpthread -ldl -lm -lc \
    -s -o ckeu
strip --strip-all --remove-section=.comment --remove-section=.note --remove-section=.gnu.version ckeu

