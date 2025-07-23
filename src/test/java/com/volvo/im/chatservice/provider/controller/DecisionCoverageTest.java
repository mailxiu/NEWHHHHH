package com.volvo.im.chatservice.provider.controller;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

// 1) 判定覆盖 (Decision Coverage)
@RunWith(Parameterized.class)
public class DecisionCoverageTest {

    private final int x;
    private final int y;
    private final int z;
    private final int expected;

    public DecisionCoverageTest(int x, int y, int z, int expected) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.expected = expected;
    }

    /**
     * Case 1: {1, 1, 4, 8}
     *
     * x > 0 和 z < 5 都为 true
     * y == 1 为 true
     * 根据 funcCoverage 方法的逻辑，当 x > 0 和 z < 5 为真时，x 增加 1。所以 x = 2.
     * 由于 y == 1 为 true， z 也会增加 1，即 z = 5.
     * 期望值计算为 x + y + z = 2 + 1 + 5 = 8.
     * Case 2: {-1, 0, 5, 4}
     *
     * x > 0 为 false, z < 5 为 true
     * y != 1 为 true
     * 当 x > 0 为假时，x 减少 1。所以 x = -2.
     * 由于 y != 1 为 true， z 减少 1，即 z = 4.
     * 期望值计算为 x + y + z = -2 + 0 + 4 = 4.
     * @return
     */
    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                {1, 1, 4, 8},   // 正确
                {-1, 0, 5, 4}   // 修正期望值为 4
        });
    }

    @Test
    public void testDecisionCoverage() {
        FuncCoverage func = new FuncCoverage();
        assertEquals(expected, func.funcCoverage(x, y, z));
    }
}