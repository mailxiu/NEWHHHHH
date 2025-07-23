package com.volvo.im.chatservice.provider.controller;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

// 3) 判定-条件覆盖 (Decision-Condition Coverage)
@RunWith(Parameterized.class)
public class DecisionConditionCoverageTest {

    private final int x;
    private final int y;
    private final int z;
    private final int expected;

    public DecisionConditionCoverageTest(int x, int y, int z, int expected) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.expected = expected;
    }

    /**
     * Case 1: {1, 1, 3, 7}
     *
     * x > 0 和 z < 5 为 true
     * y == 1 || z != 2 为 true
     * 因此，x 增加 1， x = 2.
     * z 也会增加 1，因为 y == 1 或 z != 2 为真。
     * 期望值为 x + y + z = 2 + 1 + 4 = 7.
     * Case 2: {-1, 1, 3, 3}
     *
     * x > 0 为 false
     * z < 5 为 true
     * y == 1 || z != 2 为 true
     * 因此，x 减少 1， x = -2.
     * z 增加 1，因为 y == 1 或 z != 2 为真。
     * 期望值为 x + y + z = -2 + 1 + 4 = 3.
     * Case 3: {1, 0, 6, 7}
     *
     * x > 0 为 false
     * z < 5 为 false
     * y == 1 || z != 2 为 true
     * x 减少 1， x = 0.
     * z 增加 1，因为 y == 1 或 z != 2 为真。
     * 期望值为 x + y + z = 0 + 0 + 7 = 7.
     * Case 4: {-1, 0, 6, 5}
     *
     * x > 0 为 false
     * z < 5 为 false
     * y == 1 || z != 2 为 false
     * x 减少 1， x = -2.
     * z 仍然保持 6，因为 y == 1 和 z != 2 都为假。
     * 期望值为 x + y + z = -2 + 0 + 5 = 5.
     */
    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                {1, 1, 3, 7},    // Case 1: x > 0 && z < 5 为真, y == 1 || z != 2 为真
                {-1, 1, 3, 3},   // Case 2: x > 0 && z < 5 为假, y == 1 || z != 2 为真
                { 1, 0, 6, 7},    // Case 3: x > 0 && z < 5 为假, y == 1 || z != 2 为真
                 {-1, 0, 6, 5},  // Case 4: x > 0 && z < 5 为假, y == 1 || z != 2 为假

        });
    }

    @Test
    public void testDecisionConditionCoverage() {
        assertEquals(expected, funcCoverage(x, y, z));
    }


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