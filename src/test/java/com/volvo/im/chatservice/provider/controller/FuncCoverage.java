package com.volvo.im.chatservice.provider.controller;

// 被测方法类
public class FuncCoverage {
    /**
     * 被测方法功能：
     * 1. 如果 x > 0 且 z < 5，x 增加 1；否则 x 减少 1。
     * 2. 如果 y 等于 1 或 z 不等于 2，z 增加 1；否则 z 减少 1。
     * @param x 参数 x
     * @param y 参数 y
     * @param z 参数 z
     * @return 计算结果 x + y + z
     */
    public int funcCoverage(int x, int y, int z) {
        if ((x > 0) && (z < 5))
            x++;
        else
            x--;
        if ((y == 1) || (z != 2))
            z++;
        else
            z--;
        return x + y + z;
    }
}