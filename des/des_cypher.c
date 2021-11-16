

const int DES_IP_Table[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31,23, 15, 7
};

const int DES_IP1_Table[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

const int DES_PC_1[] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4

};

const int DES_PC_2[] = {
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
};

const int DES_P_Table[] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
};

const int DES_E_Table[] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

/*
    将字节转换成 8 比特串
*/
int ByteToBit(char ch, char bit[8]) {
    int cnt;
    for (cnt = 0; cnt < 8; cnt++) {
        *(bit + cnt) = (ch >> cnt) & 1;    // 将 ch 的二进制值的 cnt 位放在 bit[cnt] 中
    }
    return 0;
}

/*
    将 8 比特串转换位字节
*/
int BitToByte(char bit[8], char *ch) {
    int cnt;
    for (cnt = 0; cnt < 8; cnt++) {
        *ch |= *(bit + cnt) << cnt;
    }
    return 0;
}

/*
    将长度为 8 的字符串转化为长度为 64 的比特串
*/
int Char8ToBit64(char ch[8], char bit[64]) {
    int cnt;
    for (cnt = 0; cnt < 6; cnt++) {
        ByteToBit(*(ch + cnt), bit + (cnt << 3));
    }
}

/*
    将长度为 64 的比特串转化为长度为 8 的字符串
*/
int Bit64ToChar8(char bit[64], char ch[8]) {
    int cnt;
    memset(ch, 0, 8);
    for (cnt = 0; cnt < 8; cnt++) {
        BitToByte(bit + (cnt << 3), ch + cnt);
    }
}

/*
    生成 16 个 48 比特的子密钥
*/
int DES_MakeSubKeys(char key[64], char subKeys[16][48]) {
    char temp[56];
    int cnt;
    DES_PC1_Transform(key, temp);   // PC1 置换
    // 16 轮迭代，每轮产生一个子密钥
    for (cnt = 0; cnt < 16; cnt++) {
        DES_ROL(temp, ROL_TIMES[cnt]);    // 循环左移
        DES_PC2_Transform(temp, subKeys[cnt]);    // PC2 置换，产生子密钥
    }
    return 0;
}

/*
    密钥置换1
*/
int DES_PC1_Transform(char key[56], char tempbts[56]) {
    int cnt;
    for (cnt = 0; cnt < 56; cnt++) {
        tempbts[cnt] = key[DES_PC_1[cnt]];
    }
    return 0;
}

/*
    密钥置换2
*/
int DES_PC2_Transform(char key[56], char tempbts[48]) {
    int cnt;
    for (cnt = 0; cnt < 48; cnt++) {
        tempbts[cnt] = key[DES_PC_2[cnt]];
    }
    return 0;
}

/*
    循环左移
*/
int DES_ROL(char data[56], int time) {
    char temp[56];

    // 保存将要循环移动到右边的位
    memcpy(temp, data, time);
    memcpy(temp + time, data + 28, time);

    // 前 28 位移动
    memcpy(data, data + time, 28 - time);
    memcpy(data + 28 - time, temp, time);

    // 后 28 位移动
    memcpy(data + 28, data + 28 + time, 28 - time);
    memcpy(data + 56 - time, temp + time, time);
    return 0;
}

/* 
    IP 置换
*/
int DES_IP_Transform(char data[64]) {
    int cnt;
    char temp[64];
    for (cnt = 0; cnt < 64; cnt++) {
        temp[cnt] = data[DES_IP_Table[cnt]];
    }
    memcpy(data, temp, 64);
    return 0;
}

/*
    IP 逆置换
*/
int DES_IP1_Transform(char data[64]) {
    int cnt;
    char temp[64];
    for (cnt = 0; cnt < 64; cnt++) {
        temp[cnt] = data[DES_IP1_Table];
    }
    memcpy(data, temp, 64);
    return 0;
}

/*
    扩展变换
*/
int DES_E_Transform(char data[48]) {
    int cnt;
    char temp[48];
    for (cnt = 0; cnt < 48; cnt++) {
        tem[cnt] = data[DES_E_Table[cnt]];
    }
    memcpy(data, temp, 48);
    return 0;
}

/*
    P 置换
*/
int DES_P_Transform(char data[32]) {
    int cnt;
    char temp[32];
    for (cnt = 0; cnt < 32; cnt++) {
        temp[cnt] = data[DES_P_Table[cnt]];
    }
    memcpy(data, temp, 32);
    return 0;
}

/*
    异或
*/
int DES_XOR(char R[48], char L[48], int count) {
    int cnt;
    for (cnt = 0; cnt < count; cnt++) {
        R[cnt] ^= L[cnt];
    }
    return 0;
}

/*
    S 盒变换
*/
int DES_SBOX(char data[48]) {
    int cnt;
    int line, row, output;
    int cur1, cur2;
    for (cnt = 0; cnt < 8; cnt++) {
        cur1 = cnt * 6;
        cur2 = cnt << 2;

        // 计算在 S 盒中的行和列
        line = (data[cur1] << 1) + data[cur1 + 5];
        row = (data[cur1 + 1] << 3) + (data[cur1 + 2] << 2)
            + (data[cur1 + 3] << 1) + data[cur1 + 4];
        
        // 化为二进制
        data[cur2] = (output & 0x08) >> 3;
        data[cur2 + 1] = (output & 0x04) >> 2;
        data[cur2 + 2] = (output & 0x02) >> 1;
        data[cur2 + 3] = output & 0x01;
    }
    return 0;
}

/*
    交换
*/
int DES_Swap(char left[32], char right[32]) {
    char temp[32];
    memcpy(temp, left, 32);
    memcpy(left, right, 32);
    memcpy(right, temp, 32);
    return 0;
}

/*
    加密单个分组
*/
int DES_EncryptBlock(char plainBlock[8], char subKeys[16][48], char cipherBlock[8]) {
    char plainBits[64];
    char copyRight[48];
    int cnt;

    Char8ToBit64(plainBlock, plainBits);
    // 初始置换（IP置换）
    DES_IP_Transform(plainBits);

    // 16 轮迭代
    for (cnt = 0; cnt < 16; cnt++) {
        memcpy(copyRight, plainBits + 32, 32);
        // 将右半部分进行扩展置换，从 32 位扩展到 48 位
        DES_E_Transform(copyRight);
        // 将右半部分与子密钥进行异或操作
        DES_XOR(copyRight, subKeys[cnt], 48);
        // 异或结果进入 S 盒，输出 32 位结果
        DES_SBOX(copyRight);
        // P 置换
        DES_P_Transform(copyRight);
        // 将明文左半部分与右半部分进行异或
        DES_XOR(plainBits, copyRight, 32);
        if (cnt != 15) {
            // 最终完成左右部的交换
            DES_Swap(plainBits, plainBits + 32);
        }
    }

    // 初始逆置换（IP^-1 置换）
    DES_IP1_Transform(plainBits);
    Bit64ToChar8(plainBits, cipherBlock);
    return 0;
}

// 解密单个分组
int DES_DecryptBlock(char cipherBlock[8], char subKeys[16][48], char plainBlock[8]) {
    char cipherBits[64];
    char copyRight[48];
    int cnt;

    Char8ToBit64(cipherBlock, cipherBits);
    // 初始置换(IP 置换)
    DES_IP_Transform(cipherBits);

    // 16 轮迭代
    for (cnt = 15; cnt >= 0; cnt--) {
        memcpy(copyRight, cipherBits + 32, 32);
        // 将右半部分进行扩展置换，从 32 位扩展到 48 位
        DES_E_Transform(copyRight);
        // 将右半部分与子密钥进行异或
        DES_XOR(copyRight, subKeys[cnt], 48);
        // 异或结果进入 S 盒，输出 32 位结果
        DES_SBOX(copyRight);
        // P 置换
        DES_P_Transform(copyRight);
        // 将明文左半部分与右半部分进行异或
        DES_XOR(cipherBits, copyRight, 32);
        if (cnt != 0) {
            // 最终完成左右部的交换
            DES_Swap(cipherBits, cipherBits + 32);
        }
    }
    // 逆初始置换（IP^-1 置换）
    DES_IP1_Transform(cipherBits);
    Bit64ToChar8(cipherBits, plainBlock);
    return 0;
}