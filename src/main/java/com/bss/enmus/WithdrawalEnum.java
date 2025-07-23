package com.bss.enmus;

import com.baomidou.mybatisplus.annotation.IEnum;
import java.io.Serializable;


public enum WithdrawalEnum
        implements IEnum<String>
{


    /* 17 */   AlipayCode("AlipayCode", "支付宝收款码"),
    /* 18 */   AlipayAccount("AlipayAccount", "支付宝账户"),
    /* 19 */   WeChatCode("WeChatCode", "微信收款码"),
    /* 20 */   WeChatAccount("WeChatAccount", "微信账户"),
    /* 21 */   BankCard("BankCard", "银行卡"),
    /* 22 */   other("other", "未知渠道");

    private final String channel;
    private final String desc;
    WithdrawalEnum(String channel, String desc) {
        this.channel = channel;
        this.desc = desc;
    }

    public String getChannel() {
        /* 24 */     return this.channel;
    } public String getDesc() {
    /* 26 */     return this.desc;
}

    public String getValue() {
        /* 30 */     return this.channel;
    }
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-04\applet_wWZCL\applet\recovery_applet-0.0.1-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\enmus\WithdrawalEnum.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */