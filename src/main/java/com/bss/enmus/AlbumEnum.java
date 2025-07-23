/*    */ package com.bss.enmus;
/*    */
/*    */ import com.baomidou.mybatisplus.annotation.IEnum;
/*    */

/*    */
/*    */ public enum AlbumEnum
        /*    */   implements IEnum<String> {
    /*    */
    /* 15 */   CURRENCY("GENERAL", "通用文章"),
    /* 16 */   PROBLEM("PROBLEM", "常见问题"),
    /* 17 */   NOTICE("NOTICE", "首页公告"),
    /* 18 */   AGREEMENT("AGREEMENT", "隐私协议");
    /*    */   public String getAlbum() {
        /* 20 */     return this.album;
        /*    */   } public String getDesc() {
        /* 22 */     return this.desc;
        /*    */   }
    /*    */
    AlbumEnum(String album, String desc) {
        /*    */     this.album = album;
        /*    */     this.desc = desc;
        /*    */   }
    /*    */
    /*    */   private final String album;
    /*    */   private final String desc;
    /*    */   public static com.bss.enmus.AlbumEnum getEnum(String album) {
        /* 26 */     for (com.bss.enmus.AlbumEnum item : values()) {
            /* 27 */       if (item.getAlbum().equals(album)) {
                /* 28 */         return item;
                /*    */       }
            /*    */     }
        /* 31 */     return CURRENCY;
        /*    */   }
    /*    */
    /*    */
    /*    */
    /*    */   public String getValue() {
        /* 37 */     return this.album;
        /*    */   }
    /*    */ }
