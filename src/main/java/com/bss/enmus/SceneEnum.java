/*     */ package com.bss.enmus;
/*     */
/*     */ import com.baomidou.mybatisplus.annotation.IEnum;
/*     */ import java.io.Serializable;
/*     */
/*     */ public enum SceneEnum
        /*     */   implements IEnum<Integer> {
    /*     */
    /*     */

    /*  15 */   OTHER(Integer.valueOf(1000), "其他"),
    /*  16 */   CODE_1001(Integer.valueOf(1001), "发现页小程序「最近使用」列表"),
    /*  17 */   CODE_1005(Integer.valueOf(1005), "微信首页顶部搜索框的搜索结果页"),
    /*  18 */   CODE_1006(Integer.valueOf(1006), "发现栏小程序主入口搜索框的搜索结果页"),
    /*  19 */   CODE_1007(Integer.valueOf(1007), "单人聊天会话中的小程序消息卡片"),
    /*  20 */   CODE_1008(Integer.valueOf(1008), "群聊会话中的小程序消息卡片"),
    /*  21 */   CODE_1010(Integer.valueOf(1010), "收藏夹"),
    /*  22 */   CODE_1011(Integer.valueOf(1011), "扫描二维码"),
    /*  23 */   CODE_1012(Integer.valueOf(1012), "长按图片识别二维码"),
    /*  24 */   CODE_1013(Integer.valueOf(1013), "扫描手机相册中选取的二维码"),
    /*  25 */   CODE_1014(Integer.valueOf(1014), "小程序订阅消息（与1107相同）"),
    /*  26 */   CODE_1017(Integer.valueOf(1017), "前往小程序体验版的入口页"),
    /*  27 */   CODE_1020(Integer.valueOf(1020), "公众号 profile 页相关小程序列表（已废弃）"),
    /*  28 */   CODE_1022(Integer.valueOf(1022), "聊天顶部置顶小程序入口（微信客户端6.6.1版本起废弃）"),
    /*  29 */   CODE_1023(Integer.valueOf(1023), "安卓系统桌面图标"),
    /*  30 */   CODE_1024(Integer.valueOf(1024), "小程序 profile 页"),
    /*  31 */   CODE_1026(Integer.valueOf(1026), "发现栏小程序主入口，「附近的小程序」列表"),
    /*  32 */   CODE_1027(Integer.valueOf(1027), "微信首页顶部搜索框搜索结果页「使用过的小程序」列表"),
    /*  33 */   CODE_1030(Integer.valueOf(1030), "自动化测试下打开小程序"),
    /*  34 */   CODE_1035(Integer.valueOf(1035), "公众号自定义菜单"),
    /*  35 */   CODE_1036(Integer.valueOf(1036), "App 分享消息卡片"),
    /*  36 */   CODE_1037(Integer.valueOf(1037), "小程序打开小程序"),
    /*  37 */   CODE_1038(Integer.valueOf(1038), "从另一个小程序返回"),
    /*  38 */   CODE_1039(Integer.valueOf(1039), "摇电视"),
    /*  39 */   CODE_1042(Integer.valueOf(1042), "添加好友搜索框的搜索结果页"),
    /*  40 */   CODE_1043(Integer.valueOf(1043), "公众号模板消息"),
    /*  41 */   CODE_1044(Integer.valueOf(1044), "带 shareTicket 的小程序消息卡片"),
    /*  42 */   CODE_1045(Integer.valueOf(1045), "朋友圈广告"),
    /*  43 */   CODE_1046(Integer.valueOf(1046), "朋友圈广告详情页"),
    /*  44 */   CODE_1047(Integer.valueOf(1047), "扫描小程序码"),
    /*  45 */   CODE_1048(Integer.valueOf(1048), "长按图片识别小程序码"),
    /*  46 */   CODE_1049(Integer.valueOf(1049), "扫描手机相册中选取的小程序码"),
    /*  47 */   CODE_1053(Integer.valueOf(1053), "搜一搜的结果页"),
    /*  48 */   CODE_1054(Integer.valueOf(1054), "顶部搜索框小程序快捷入口（微信客户端版本6.7.4起废弃）"),
    /*  49 */   CODE_1056(Integer.valueOf(1056), "聊天顶部音乐播放器右上角菜单"),
    /*  50 */   CODE_1058(Integer.valueOf(1058), "公众号文章"),
    /*  51 */   CODE_1059(Integer.valueOf(1059), "体验版小程序绑定邀请页"),
    /*  52 */   CODE_1065(Integer.valueOf(1065), "URL scheme "),
    /*  53 */   CODE_1067(Integer.valueOf(1067), "公众号文章广告"),
    /*  54 */   CODE_1069(Integer.valueOf(1069), "移动应用通过openSDK进入微信，打开小程序"),
    /*  55 */   CODE_1073(Integer.valueOf(1073), "客服消息列表下发的小程序消息卡片"),
    /*  56 */   CODE_1074(Integer.valueOf(1074), "公众号会话下发的小程序消息卡片"),
    /*  57 */   CODE_1077(Integer.valueOf(1077), "摇周边"),
    /*  58 */   CODE_1081(Integer.valueOf(1081), "客服消息下发的文字链"),
    /*  59 */   CODE_1082(Integer.valueOf(1082), "公众号会话下发的文字链"),
    /*  60 */   CODE_1084(Integer.valueOf(1084), "朋友圈广告原生页"),
    /*  61 */   CODE_1088(Integer.valueOf(1088), "会话中查看系统消息，打开小程序"),
    /*  62 */   CODE_1089(Integer.valueOf(1089), "微信聊天主界面下拉，「最近使用」栏（基础库2.2.4-2.29.0版本包含「我的小程序」栏，2.29.1版本起仅为「最近使用」栏"),
    /*  63 */   CODE_1090(Integer.valueOf(1090), "长按小程序右上角菜单唤出最近使用历史"),
    /*  64 */   CODE_1091(Integer.valueOf(1091), "公众号文章商品卡片"),
    /*  65 */   CODE_1092(Integer.valueOf(1092), "城市服务入口"),
    /*  66 */   CODE_1095(Integer.valueOf(1095), "小程序广告组件"),
    /*  67 */   CODE_1096(Integer.valueOf(1096), "聊天记录，打开小程序"),
    /*  68 */   CODE_1099(Integer.valueOf(1099), "页面内嵌插件"),
    /*  69 */   CODE_1100(Integer.valueOf(1100), "红包封面详情页打开小程序"),
    /*  70 */   CODE_1101(Integer.valueOf(1101), "远程调试热更新（开发者工具中，预览 -> 自动预览 -> 编译并预览）"),
    /*  71 */   CODE_1102(Integer.valueOf(1102), "公众号 profile 页服务预览"),
    /*  72 */   CODE_1103(Integer.valueOf(1103), "发现页小程序「我的小程序」列表（基础库2.2.4-2.29.0版本废弃，2.29.1版本起生效）"),
    /*  73 */   CODE_1104(Integer.valueOf(1104), "微信聊天主界面下拉，「我的小程序」栏（基础库2.2.4-2.29.0版本废弃，2.29.1版本起生效）"),
    /*  74 */   CODE_1106(Integer.valueOf(1106), "聊天主界面下拉，从顶部搜索结果页，打开小程序"),
    /*  75 */   CODE_1107(Integer.valueOf(1107), "订阅消息，打开小程序"),
    /*  76 */   CODE_1119(Integer.valueOf(1119), "【企业微信】工作台内打开小程序"),
    /*  77 */   CODE_1120(Integer.valueOf(1120), "【企业微信】个人资料页内打开小程序"),
    /*  78 */   CODE_1121(Integer.valueOf(1121), "【企业微信】聊天加号附件框内打开小程序"),
    /*  79 */   CODE_1129(Integer.valueOf(1129), "微信爬虫访问"),
    /*  80 */   CODE_1131(Integer.valueOf(1131), "浮窗（8.0版本起仅包含被动浮窗）"),
    /*  81 */   CODE_1133(Integer.valueOf(1133), "硬件设备打开小程序"),
    /*  82 */   CODE_1135(Integer.valueOf(1135), "小程序profile页相关小程序列表，打开小程序"),
    /*  83 */   CODE_1144(Integer.valueOf(1144), "公众号文章 - 视频贴片"),
    /*  84 */   CODE_1145(Integer.valueOf(1145), "发现栏 - 发现小程序"),
    /*  85 */   CODE_1152(Integer.valueOf(1152), "订阅号视频打开小程序"),
    /*  86 */   CODE_1154(Integer.valueOf(1154), "朋友圈内打开“单页模式”"),
    /*  87 */   CODE_1157(Integer.valueOf(1157), "“服务号会话页打开小程序"),
    /*  88 */   CODE_1158(Integer.valueOf(1158), "群工具打开小程序"),
    /*  89 */   CODE_1160(Integer.valueOf(1160), "群待办"),
    /*  90 */   CODE_1167(Integer.valueOf(1167), "H5 通过开放标签打开小程序"),
    /*  91 */   CODE_1168(Integer.valueOf(1168), "移动/网站应用直接运行小程序"),
    /*  92 */   CODE_1169(Integer.valueOf(1169), "发现栏小程序主入口，各个生活服务入口（例如快递服务、出行服务等）"),
    /*  93 */   CODE_1173(Integer.valueOf(1173), "聊天素材用小程序打开"),
    /*  94 */   CODE_1175(Integer.valueOf(1175), "视频号主页商店入口"),
    /*  95 */   CODE_1176(Integer.valueOf(1176), "视频号直播间主播打开小程序"),
    /*  96 */   CODE_1178(Integer.valueOf(1178), "在电脑打开手机上打开的小程序"),
    /*  97 */   CODE_1179(Integer.valueOf(1179), "#话题页打开小程序"),
    /*  98 */   CODE_1181(Integer.valueOf(1181), "网站应用打开PC小程序"),
    /*  99 */   CODE_1183(Integer.valueOf(1183), "PC微信 - 小程序面板 - 发现小程序 - 搜索"),
    /* 100 */   CODE_1184(Integer.valueOf(1184), "视频号链接打开小程序"),
    /* 101 */   CODE_1185(Integer.valueOf(1185), "群公告"),
    /* 102 */   CODE_1186(Integer.valueOf(1186), "收藏 - 笔记"),
    /* 103 */   CODE_1187(Integer.valueOf(1187), "浮窗（8.0版本起）"),
    /* 104 */   CODE_1191(Integer.valueOf(1191), "视频号活动"),
    /* 105 */   CODE_1193(Integer.valueOf(1193), "视频号主页服务菜单打开小程序"),
    /* 106 */   CODE_1194(Integer.valueOf(1194), "URL Link"),
    /* 107 */   CODE_1196(Integer.valueOf(1196), "个人状态打开小程序"),
    /* 108 */   CODE_1201(Integer.valueOf(1201), "视频号广告详情页打开小程序"),
    /* 109 */   CODE_1202(Integer.valueOf(1202), "企微客服号会话打开小程序卡片"),
    /* 110 */   CODE_1207(Integer.valueOf(1207), "企微客服号会话打开小程序文字链"),
    /* 111 */   CODE_1218(Integer.valueOf(1218), "微信键盘预览打开小程序"),
    /* 112 */   CODE_1226(Integer.valueOf(1226), "聊天消息在设备打开后打开小程序"),
    /* 113 */   CODE_1230(Integer.valueOf(1230), "订阅号H5广告进入小程序"),
    /* 114 */   CODE_1231(Integer.valueOf(1231), "动态消息提醒入口打开小程序"),
    /* 115 */   CODE_1232(Integer.valueOf(1232), "搜一搜竞价广告打开小程序"),
    /* 116 */   CODE_1238(Integer.valueOf(1238), "看一看信息流广告打开小程序"),
    /* 117 */   CODE_1244(Integer.valueOf(1244), "#tag搜索结果页打开小程序"),
    /* 118 */   CODE_1248(Integer.valueOf(1248), "通过小程序账号迁移进入小程序"),
    /* 119 */   CODE_1252(Integer.valueOf(1252), "搜一搜小程序搜索页「小功能」模块进入小程序"),
    /* 120 */   CODE_1254(Integer.valueOf(1254), "发现页「动态」卡片 打开小程序"),
    /* 121 */   CODE_1255(Integer.valueOf(1255), "发现页「我的」卡片 打开小程序"),
    /* 122 */   CODE_1265(Integer.valueOf(1265), "小程序图片详情页打开小程序"),
    /* 123 */   CODE_1266(Integer.valueOf(1266), "小程序图片长按半屏入口打开小程序"),
    /* 124 */   CODE_1267(Integer.valueOf(1267), "小程序图片会话角标打开小程序"),
    /* 125 */   CODE_1271(Integer.valueOf(1271), "微信聊天主界面下拉，「我的常用小程序」栏"),
    /* 126 */   CODE_1278(Integer.valueOf(1278), "发现页「发现小程序」列表打开小程序"),
    /* 127 */   CODE_1279(Integer.valueOf(1279), "发现页「发现小程序」合集页打开小程序"),
    /* 128 */   CODE_1280(Integer.valueOf(1280), "下拉任务栏小程序垂搜「建议使用」打开小程序"),
    /* 129 */   CODE_1281(Integer.valueOf(1281), "下拉任务栏小程序垂搜「发现小程序」打开小程序"),
    /* 130 */   CODE_1286(Integer.valueOf(1286), "明文scheme打开小程序");
    /*     */   private final Integer scene;
    /*     */   private final String desc;
    SceneEnum(Integer scene, String desc) {
        /*     */     this.scene = scene;
        /*     */     this.desc = desc;
        /*     */   };

    /*     */   public Integer getScene() {
        /* 132 */     return this.scene;
        /*     */   } public String getDesc() {
        /* 134 */     return this.desc;
        /*     */   }
    /*     */
    /*     */   public static com.bss.enmus.SceneEnum getEnum(Integer scene) {
        /* 138 */     for (com.bss.enmus.SceneEnum item : values()) {
            /* 139 */       if (item.getScene().equals(scene)) {
                /* 140 */         return item;
                /*     */       }
            /*     */     }
        /*     */
        /* 144 */     return OTHER;
        /*     */   }
    /*     */
    /*     */
    /*     */   public Integer getValue() {
        /* 149 */     return this.scene;
        /*     */   }
    /*     */ }

