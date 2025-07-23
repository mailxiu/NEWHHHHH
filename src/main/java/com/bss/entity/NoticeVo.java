/*    */
package com.bss.entity;
/*    */
/*    */

import com.baomidou.mybatisplus.annotation.TableName;
/*    */ import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("notice")
/*    */ public class NoticeVo implements Serializable {
    /*    */   private String merchant;
    /*    */   private String info;
    /*    */   private Integer speed;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.NoticeVo)) return false;
        com.bss.entity.NoticeVo other = (com.bss.entity.NoticeVo) o;
        if (!other.canEqual(this)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$info = getInfo(), other$info = other.getInfo();
        if (!Objects.equals(this$info, other$info)) return false;
        Object this$speed = getSpeed(), other$speed = other.getSpeed();
        return !(!Objects.equals(this$speed, other$speed));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.NoticeVo;
    }


    public String toString() {
        return "NoticeVo(merchant=" + getMerchant() + ", info=" + getInfo() + ", speed=" + getSpeed() + ")";
    }

    /*    */
    /*    */
    public String getMerchant() {
        /* 16 */
        return this.merchant;
        /*    */
    }

    /*    */
    /*    */
    public void setMerchant(String merchant) {
        /* 13 */
        this.merchant = merchant;
    }

    public String getInfo() {
        /* 18 */
        return this.info;
        /*    */
    }

    public void setInfo(String info) {
        this.info = info;
    }

    public Integer getSpeed() {
        /* 20 */
        return this.speed;
        /*    */
    }

    public void setSpeed(Integer speed) {
        this.speed = speed;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\NoticeVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */