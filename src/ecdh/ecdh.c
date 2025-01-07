#include "ecdh.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>


// 从/dev/random读取随机字节
static int get_random_bytes(void *buf, size_t len) {
    int fd = open("/dev/random", O_RDONLY);
    if (fd == -1) return -1;
    
    size_t read_bytes = 0;
    while (read_bytes < len) {
        ssize_t result = read(fd, (char*)buf + read_bytes, len - read_bytes);
        if (result < 0) {
            close(fd);
            return -1;
        }
        read_bytes += result;
    }
    
    close(fd);
    return 0;
}

void ec_init_point(ECPoint *point) {
    mpz_init(point->x);
    mpz_init(point->y);
    point->infinity = 0;
}

void ec_clear_point(ECPoint *point) {
    mpz_clear(point->x);
    mpz_clear(point->y);
}

void ec_init_curve(ECurve *curve) {
    mpz_init(curve->p);
    mpz_init(curve->a);
    mpz_init(curve->b);
    mpz_init(curve->n);
    ec_init_point(&curve->G);
}

void ec_clear_curve(ECurve *curve) {
    mpz_clear(curve->p);
    mpz_clear(curve->a);
    mpz_clear(curve->b);
    mpz_clear(curve->n);
    ec_clear_point(&curve->G);
}

static void ec_point_add(ECPoint *result, const ECPoint *p1, const ECPoint *p2, const ECurve *curve) {
    if (p1->infinity) {
        mpz_set(result->x, p2->x);
        mpz_set(result->y, p2->y);
        result->infinity = p2->infinity;
        return;
    }
    if (p2->infinity) {
        mpz_set(result->x, p1->x);
        mpz_set(result->y, p1->y);
        result->infinity = p1->infinity;
        return;
    }

    mpz_t lambda, temp1, temp2, temp3;
    mpz_init(lambda);
    mpz_init(temp1);
    mpz_init(temp2);
    mpz_init(temp3);

    // 检查是否是同一点
    if (mpz_cmp(p1->x, p2->x) == 0) {
        if (mpz_cmp(p1->y, p2->y) != 0) {
            // P + (-P) = O
            result->infinity = 1;
            goto cleanup;
        }
        // 检查是否是y=0的点
        if (mpz_cmp_ui(p1->y, 0) == 0) {
            result->infinity = 1;
            goto cleanup;
        }
        // 点加倍: lambda = (3x^2 + a) / (2y)
        mpz_mul(temp1, p1->x, p1->x);
        mpz_mod(temp1, temp1, curve->p);
        mpz_mul_ui(temp1, temp1, 3);
        mpz_add(temp1, temp1, curve->a);
        mpz_mod(temp1, temp1, curve->p);

        mpz_mul_ui(temp2, p1->y, 2);
        if (!mpz_invert(temp2, temp2, curve->p)) {
            result->infinity = 1;
            goto cleanup;
        }
        
        mpz_mul(lambda, temp1, temp2);
        mpz_mod(lambda, lambda, curve->p);
    } else {
        // 点加法: lambda = (y2-y1)/(x2-x1)
        mpz_sub(temp1, p2->y, p1->y);
        mpz_mod(temp1, temp1, curve->p);
        
        mpz_sub(temp2, p2->x, p1->x);
        mpz_mod(temp2, temp2, curve->p);
        
        if (!mpz_invert(temp2, temp2, curve->p)) {
            result->infinity = 1;
            goto cleanup;
        }
        
        mpz_mul(lambda, temp1, temp2);
        mpz_mod(lambda, lambda, curve->p);
    }

    // x3 = lambda^2 - x1 - x2
    mpz_mul(result->x, lambda, lambda);
    mpz_sub(result->x, result->x, p1->x);
    mpz_sub(result->x, result->x, p2->x);
    mpz_mod(result->x, result->x, curve->p);

    // y3 = lambda(x1 - x3) - y1
    mpz_sub(temp1, p1->x, result->x);
    mpz_mul(temp1, lambda, temp1);
    mpz_sub(result->y, temp1, p1->y);
    mpz_mod(result->y, result->y, curve->p);

    result->infinity = 0;

cleanup:
    mpz_clear(lambda);
    mpz_clear(temp1);
    mpz_clear(temp2);
    mpz_clear(temp3);
}

void ec_point_mul(ECPoint *result, const ECPoint *p, const mpz_t k, const ECurve *curve) {
    // 处理特殊情况
    if (p->infinity || mpz_cmp_ui(k, 0) == 0) {
        result->infinity = 1;
        return;
    }
    
    ECPoint R0, R1, temp;
    ec_init_point(&R0);
    ec_init_point(&R1);
    ec_init_point(&temp);
    
    // R0 = O, R1 = P
    R0.infinity = 1;
    mpz_set(R1.x, p->x);
    mpz_set(R1.y, p->y);
    R1.infinity = 0;
    
    // 从最高位开始处理
    for (int i = mpz_sizeinbase(k, 2) - 1; i >= 0; i--) {
        if (mpz_tstbit(k, i)) {
            // 如果当前位为1: R0 = R0 + R1, R1 = 2R1
            ec_point_add(&temp, &R0, &R1, curve);  // temp = R0 + R1
            mpz_set(R0.x, temp.x);                 // R0 = temp
            mpz_set(R0.y, temp.y);
            R0.infinity = temp.infinity;
            
            ec_point_add(&temp, &R1, &R1, curve);  // temp = 2R1
            mpz_set(R1.x, temp.x);                 // R1 = temp
            mpz_set(R1.y, temp.y);
            R1.infinity = temp.infinity;
        } else {
            // 如果当前位为0: R1 = R0 + R1, R0 = 2R0
            ec_point_add(&temp, &R0, &R1, curve);  // temp = R0 + R1
            mpz_set(R1.x, temp.x);                 // R1 = temp
            mpz_set(R1.y, temp.y);
            R1.infinity = temp.infinity;
            
            ec_point_add(&temp, &R0, &R0, curve);  // temp = 2R0
            mpz_set(R0.x, temp.x);                 // R0 = temp
            mpz_set(R0.y, temp.y);
            R0.infinity = temp.infinity;
        }
    }
    
    // 结果在R0中
    mpz_set(result->x, R0.x);
    mpz_set(result->y, R0.y);
    result->infinity = R0.infinity;
    
    // 释放临时变量
    ec_clear_point(&R0);
    ec_clear_point(&R1);
    ec_clear_point(&temp);
}

void generate_keypair(mpz_t private_key, ECPoint *public_key, const ECurve *curve) {
    // 使用足够的字节来生成私钥
    unsigned char random_bytes[32];  // 256位随机数
    if (get_random_bytes(random_bytes, sizeof(random_bytes)) < 0) {
        fprintf(stderr, "Error: Failed to read from /dev/random\n");
        exit(1);
    }
    
    // 将随机字节转换为mpz_t
    mpz_import(private_key, sizeof(random_bytes), 1, 1, 0, 0, random_bytes);
    
    // 确保私钥在正确范围内 (1 < private_key < n-1)
    mpz_mod(private_key, private_key, curve->n);
    if (mpz_cmp_ui(private_key, 1) <= 0) {
        mpz_add_ui(private_key, private_key, 2);  // 如果太小，加2确保大于1
    }
    
    // 计算公钥 Q = kG
    ec_point_mul(public_key, &curve->G, private_key, curve);
}

void compute_shared_secret(mpz_t shared_secret, const ECPoint *others_public, const mpz_t my_private, const ECurve *curve) {
    ECPoint shared_point;
    ec_init_point(&shared_point);
    
    // 计算共享点: shared_point = my_private * others_public
    ec_point_mul(&shared_point, others_public, my_private, curve);
    
    // 使用x坐标作为共享密钥
    mpz_set(shared_secret, shared_point.x);
    
    ec_clear_point(&shared_point);
}