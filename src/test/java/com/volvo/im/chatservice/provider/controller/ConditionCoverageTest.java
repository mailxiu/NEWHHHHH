package com.volvo.im.chatservice.provider.controller;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

// 2) 条件覆盖 (Condition Coverage)
@RunWith(Parameterized.class)
public class ConditionCoverageTest {

    private final int x;
    private final int y;
    private final int z;
    private final int expected;

    public ConditionCoverageTest(int x, int y, int z, int expected) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.expected = expected;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                {1, 0, 4, 7},   // x > 0 = true, z < 5 = true, y != 1 = false, z != 2 = true

        });
    }

    @Test
    public void testConditionCoverage() {
        assertEquals(expected, funcCoverage(x, y, z));
    }


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