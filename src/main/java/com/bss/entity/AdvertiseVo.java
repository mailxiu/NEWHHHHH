/*    */
package com.bss.entity;
/*    */
/*    */

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */ public class AdvertiseVo implements Serializable {
    /*    */   private String md;
    /*    */   private Integer orient;
    /*    */   private Integer state;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.AdvertiseVo)) return false;
        com.bss.entity.AdvertiseVo other = (com.bss.entity.AdvertiseVo) o;
        if (!other.canEqual(this)) return false;
        Object this$md = getMd(), other$md = other.getMd();
        if (!Objects.equals(this$md, other$md)) return false;
        Object this$orient = getOrient(), other$orient = other.getOrient();
        if (!Objects.equals(this$orient, other$orient)) return false;
        Object this$state = getState(), other$state = other.getState();
        return !(!Objects.equals(this$state, other$state));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.AdvertiseVo;
    }



    public String toString() {
        return "AdvertiseVo(md=" + getMd() + ", orient=" + getOrient() + ", state=" + getState() + ")";
    }

    /*    */
    /*    */
    public String getMd() {
        /* 14 */
        return this.md;
        /*    */
    }

    /*    */
    /*    */
    public void setMd(String md) {
        /* 11 */
        this.md = md;
    }

    public Integer getOrient() {
        /* 16 */
        return this.orient;
        /*    */
    }

    public void setOrient(Integer orient) {
        this.orient = orient;
    }

    public Integer getState() {
        /* 18 */
        return this.state;
        /*    */
    }

    public void setState(Integer state) {
        this.state = state;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\AdvertiseVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */