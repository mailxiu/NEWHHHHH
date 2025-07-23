package com.bss.enmus;

import com.baomidou.mybatisplus.annotation.IEnum;
import java.io.Serializable;

public enum SourceEnum
        implements IEnum<Integer> {


    /* 15 */   OTHER(Integer.valueOf(10), "其他"),
    /* 16 */   CODE_1(Integer.valueOf(1), "小程序历史列表"),
    /* 17 */   CODE_2(Integer.valueOf(2), "搜索"),
    /* 18 */   CODE_3(Integer.valueOf(3), "会话"),
    /* 19 */   CODE_4(Integer.valueOf(4), "扫一扫二维码"),
    /* 20 */   CODE_5(Integer.valueOf(5), "公众号主页"),
    /* 21 */   CODE_6(Integer.valueOf(6), "聊天顶部"),
    /* 22 */   CODE_7(Integer.valueOf(7), "系统桌面"),
    /* 23 */   CODE_8(Integer.valueOf(8), "小程序主页"),
    /* 24 */   CODE_9(Integer.valueOf(9), "附近的小程序"),
    /* 25 */   CODE_11(Integer.valueOf(11), "模板消息"),
    /* 26 */   CODE_12(Integer.valueOf(12), "客服消息"),
    /* 27 */   CODE_13(Integer.valueOf(13), "公众号菜单"),
    /* 28 */   CODE_14(Integer.valueOf(14), "APP分享"),
    /* 29 */   CODE_15(Integer.valueOf(15), "支付完成页"),
    /* 30 */   CODE_16(Integer.valueOf(16), "长按识别二维码"),
    /* 31 */   CODE_17(Integer.valueOf(17), "相册选取二维码"),
    /* 32 */   CODE_18(Integer.valueOf(18), "公众号文章"),
    /* 33 */   CODE_19(Integer.valueOf(19), "钱包"),
    /* 34 */   CODE_20(Integer.valueOf(20), "卡包"),
    /* 35 */   CODE_21(Integer.valueOf(21), "小程序内卡券"),
    /* 36 */   CODE_22(Integer.valueOf(22), "其他小程序"),
    /* 37 */   CODE_23(Integer.valueOf(23), "其他小程序返回"),
    /* 38 */   CODE_24(Integer.valueOf(24), "卡券适用门店列表"),
    /* 39 */   CODE_25(Integer.valueOf(25), "搜索框快捷入口"),
    /* 40 */   CODE_26(Integer.valueOf(26), "小程序客服消息"),
    /* 41 */   CODE_27(Integer.valueOf(27), "公众号下发"),
    /* 42 */   CODE_28(Integer.valueOf(28), "系统会话菜单"),
    /* 43 */   CODE_29(Integer.valueOf(29), "任务栏-最近使用"),
    /* 44 */   CODE_30(Integer.valueOf(30), "长按小程序菜单圆点"),
    /* 45 */   CODE_31(Integer.valueOf(31), "连wifi成功页"),
    /* 46 */   CODE_32(Integer.valueOf(32), "城市服务"),
    /* 47 */   CODE_33(Integer.valueOf(33), "微信广告"),
    /* 48 */   CODE_34(Integer.valueOf(34), "其他移动应用"),
    /* 49 */   CODE_35(Integer.valueOf(35), "发现入口-我的小程序"),
    /* 50 */   CODE_36(Integer.valueOf(36), "任务栏-我的小程序"),
    /* 51 */   CODE_37(Integer.valueOf(37), "微信圈子"),
    /* 52 */   CODE_38(Integer.valueOf(38), "手机充值"),
    /* 53 */   CODE_39(Integer.valueOf(39), "H5"),
    /* 54 */   CODE_40(Integer.valueOf(40), "插件"),
    /* 55 */   CODE_41(Integer.valueOf(41), "大家在用"),
    /* 56 */   CODE_42(Integer.valueOf(42), "发现页"),
    /* 57 */   CODE_43(Integer.valueOf(43), "浮窗"),
    /* 58 */   CODE_44(Integer.valueOf(44), "附近的人"),
    /* 59 */   CODE_45(Integer.valueOf(45), "看一看"),
    /* 60 */   CODE_46(Integer.valueOf(46), "朋友圈"),
    /* 61 */   CODE_47(Integer.valueOf(47), "企业微信"),
    /* 62 */   CODE_48(Integer.valueOf(48), "视频"),
    /* 63 */   CODE_49(Integer.valueOf(49), "收藏"),
    /* 64 */   CODE_50(Integer.valueOf(50), "微信红包"),
    /* 65 */   CODE_51(Integer.valueOf(51), "微信游戏中心"),
    /* 66 */   CODE_52(Integer.valueOf(52), "摇一摇"),
    /* 67 */   CODE_53(Integer.valueOf(53), "公众号导购消息"),
    /* 68 */   CODE_54(Integer.valueOf(54), "识物"),
    /* 69 */   CODE_55(Integer.valueOf(55), "小程序订单"),
    /* 70 */   CODE_56(Integer.valueOf(56), "小程序直播"),
    /* 71 */   CODE_57(Integer.valueOf(57), "群工具");

    private final Integer scene;
    private final String desc;
    SourceEnum(Integer scene, String desc) {
        this.scene = scene;
        this.desc = desc;
    }
    public Integer getScene() {
        /* 73 */     return this.scene;
    } public String getDesc() {
        /* 75 */     return this.desc;
    }

    public static com.bss.enmus.SourceEnum getEnum(Integer scene) {
        /* 79 */     for (com.bss.enmus.SourceEnum item : values()) {
            /* 80 */       if (item.getScene().equals(scene)) {
                /* 81 */         return item;
            }
        }

        /* 85 */     return OTHER;
    }


    public Integer getValue() {
        /* 90 */     return this.scene;
    }
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-04\applet_wWZCL\applet\recovery_applet-0.0.1-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\enmus\SourceEnum.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */