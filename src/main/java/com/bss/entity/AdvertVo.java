/*    */
package com.bss.entity;

import java.util.Objects;

/*    */
/*    */ public class AdvertVo {
    /*    */   private String type;
    /*    */   private String ad;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.AdvertVo)) return false;
        com.bss.entity.AdvertVo other = (com.bss.entity.AdvertVo) o;
        if (!other.canEqual(this)) return false;
        Object this$type = getType(), other$type = other.getType();
        if (!Objects.equals(this$type, other$type)) return false;
        Object this$ad = getAd(), other$ad = other.getAd();
        return !(!Objects.equals(this$ad, other$ad));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.AdvertVo;
    }



    public String toString() {
        return "AdvertVo(type=" + getType() + ", ad=" + getAd() + ")";
    }

    /*    */
    /*    */
    public String getType() {
        /* 11 */
        return this.type;
        /*    */
    }

    /*    */
    /*    */
    public void setType(String type) {
        /*  8 */
        this.type = type;
    }

    public String getAd() {
        /* 13 */
        return this.ad;
        /*    */
    }

    public void setAd(String ad) {
        this.ad = ad;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\AdvertVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */