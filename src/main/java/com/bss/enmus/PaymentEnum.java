package com.bss.enmus;

import com.baomidou.mybatisplus.annotation.IEnum;
import java.io.Serializable;


public enum PaymentEnum
        implements IEnum<String>
{
    HuiFuQuick("HuiFuQuick", "汇付斗拱-银行卡"),
    WeChatApp("WeChatApp", "微信支付APP"),
    /* 17 */   WeChat("WeChat", "小程序支付"),
    /* 18 */   WeChatJSAPI("WeChatJSAPI", "公众号支付"),
    /* 19 */   Alipay("Alipay", "支付宝支付"),
    AlipayApp("AlipayApp", "支付宝App"),
    /* 20 */   YSWxPay("YSWxPay", "银盛微信支付"),
    /* 21 */   SendPay("SendPay", "杉德支付-银行卡"),
    /* 22 */   SendYLPay("SendYLPay", "杉德支付-银联扫码"),
    /* 23 */   Advance("Advance", "储值卡支付");


    private final String state;
    private final String desc;

    PaymentEnum(String state, String desc) {
        this.state = state;
        this.desc = desc;
    }

    public String getState() {
        /* 25 */     return this.state;
    } public String getDesc() {
    /* 27 */     return this.desc;
}

    public String getValue() {
        /* 31 */     return this.state;
    }
}

