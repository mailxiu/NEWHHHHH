package com.volvo.im.chatservice.provider.controller;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

// 4) 条件组合覆盖 (Condition Combination Coverage)
@RunWith(Parameterized.class)
public class ConditionCombinationCoverageTest {

    private final int x;
    private final int y;
    private final int z;
    private final int expected;

    public ConditionCombinationCoverageTest(int x, int y, int z, int expected) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.expected = expected;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {-1, 1, 3, 3},  // x > 0 = false, z < 5 = true, y == 1 = true, z != 2 = true
        });
    }

    @Test
    public void testConditionCombinationCoverage() {
        FuncCoverage func = new FuncCoverage();
        assertEquals(expected, func.funcCoverage(x, y, z));
    }
}